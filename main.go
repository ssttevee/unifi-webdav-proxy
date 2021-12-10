package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/gorilla/websocket"
	"github.com/koding/websocketproxy"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/net/webdav"
)

func isWebDAVUA(ua string) bool {
	return strings.HasPrefix(ua, "WebDAVLib/") || strings.HasPrefix(ua, "WebDAVFS/") || strings.HasPrefix(ua, "Cyberduck/")
}

const unifiHostname = "localhost"
const unifiBasedir = "/var/lib/unifi"

type FilteredWebDAVDir struct {
	webdav.FileSystem

	filter func(string) bool
}

func (d *FilteredWebDAVDir) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if !d.filter(name) {
		return os.ErrNotExist
	}

	return d.FileSystem.Mkdir(ctx, name, perm)
}

func (d *FilteredWebDAVDir) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if !d.filter(name) {
		return nil, os.ErrNotExist
	}

	return d.FileSystem.OpenFile(ctx, name, flag, perm)
}

func (d *FilteredWebDAVDir) RemoveAll(ctx context.Context, name string) error {
	if !d.filter(name) {
		return os.ErrNotExist
	}

	return d.FileSystem.RemoveAll(ctx, name)
}

func (d *FilteredWebDAVDir) Rename(ctx context.Context, oldName, newName string) error {
	if !d.filter(oldName) {
		return os.ErrNotExist
	}

	return d.FileSystem.Rename(ctx, oldName, newName)
}

func (d *FilteredWebDAVDir) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if !d.filter(name) {
		return nil, os.ErrNotExist
	}

	return d.FileSystem.Stat(ctx, name)
}

type UnifiWebDAV struct {
	admins     *mongo.Collection
	sites      *mongo.Collection
	privileges *mongo.Collection

	ls webdav.LockSystem
	fs webdav.FileSystem
}

func (u *UnifiWebDAV) validateUser(r *http.Request) (string, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", nil
	}

	var result bson.M
	if err := u.admins.FindOne(r.Context(), bson.M{"name": username}).Decode(&result); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", nil
		}

		return "", err
	}

	if err := sha512_crypt.New().Verify(result["x_shadow"].(string), []byte(password)); err != nil {
		if errors.Is(err, crypt.ErrKeyMismatch) {
			return "", nil
		}

		return "", err
	}

	return result["_id"].(primitive.ObjectID).Hex(), nil
}

func (u *UnifiWebDAV) getUserFilter(ctx context.Context, id string) (func(string) bool, error) {
	it, err := u.privileges.Find(ctx, bson.M{"admin_id": id, "role": "admin"})
	if err != nil {
		return nil, err
	}

	var siteIDs bson.A

	var result bson.M
	for it.Next(ctx) {
		if err := it.Decode(&result); err != nil {
			return nil, err
		}

		siteID, err := primitive.ObjectIDFromHex(result["site_id"].(string))
		if err != nil {
			return nil, err
		}

		siteIDs = append(siteIDs, siteID)
	}

	if err := it.Err(); err != nil {
		return nil, err
	}

	if len(siteIDs) == 0 {
		return func(string) bool {
			return false
		}, nil
	}

	it, err = u.sites.Find(ctx, bson.M{"_id": bson.M{"$in": siteIDs}})
	if err != nil {
		return nil, err
	}

	siteNames := make(map[string]bool, len(siteIDs))

	for it.Next(ctx) {
		if err := it.Decode(&result); err != nil {
			return nil, err
		}

		siteNames[result["name"].(string)] = true
	}

	if err := it.Err(); err != nil {
		return nil, err
	}

	return func(name string) bool {
		if len(name) == 0 {
			return false
		}

		if name[0] == '/' {
			name = name[1:]
		}

		if pos := strings.Index(name, "/"); pos != -1 {
			name = name[:pos]
		}

		return name == "" || siteNames[name]
	}, nil
}

func (u *UnifiWebDAV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := u.validateUser(r)
	if id == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+r.Host+`"`)

		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Println(err)

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	filter, err := u.getUserFilter(r.Context(), id)
	if err != nil {
		log.Println(err)

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	(&webdav.Handler{
		FileSystem: &FilteredWebDAVDir{
			FileSystem: u.fs,
			filter:     filter,
		},
		LockSystem: webdav.NewMemLS(),
	}).ServeHTTP(w, r)
}

func shouldRedirect(proto, hostname, port string) bool {
	if proto == "http" && port == ":8080" {
		return false
	}

	if proto == "https" && port == "" {
		return false
	}

	return true
}

func main() {
	mock := flag.String("m", "", "mock origin")
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()

	controlPanelOrigin := "https://" + unifiHostname + ":8443"
	informEndpointOrigin := "http://" + unifiHostname + ":8080"

	cfg := tls.Config{InsecureSkipVerify: true}

	wsProxy := websocketproxy.NewProxy(&url.URL{
		Scheme: "wss",
		Host:   unifiHostname + ":8443",
	})

	wsProxy.Dialer = &websocket.Dialer{
		TLSClientConfig: &cfg,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &cfg,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mongoClient, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27117"))
	if err != nil {
		panic(err)
	}

	ace := mongoClient.Database("ace")

	handler := UnifiWebDAV{
		admins:     ace.Collection("admin"),
		sites:      ace.Collection("site"),
		privileges: ace.Collection("privilege"),

		ls: webdav.NewMemLS(),
		fs: webdav.Dir(path.Join(unifiBasedir, "data/sites")),
	}

	http.ListenAndServe(":44412", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var port string
		hostname := r.Host
		if pos := strings.Index(hostname, ":"); pos != -1 {
			port = hostname[pos:]
			hostname = hostname[:pos]
		}

		proto := r.Header.Get("X-Forwarded-Proto")
		if *verbose {
			log.Printf("%s %s://%s %s %s", r.Method, proto, hostname, port, r.URL.Path)
			for k, vs := range r.Header {
				for _, v := range vs {
					fmt.Printf("%s: %s\n", k, v)
				}
			}
		}

		if proto == "https" && isWebDAVUA(r.Header.Get("User-Agent")) {
			handler.ServeHTTP(w, r)
			return
		}

		tail := r.URL.Path
		if r.URL.RawQuery != "" {
			tail += "?" + r.URL.RawQuery
		}

		var origin string = *mock
		if proto == "" {
			if *verbose {
				log.Println("probably a local connection")
			}

			origin = controlPanelOrigin
		} else if shouldRedirect(proto, hostname, port) {
			http.Redirect(w, r, "https://"+hostname+tail, http.StatusMovedPermanently)
			return
		} else if origin == "" {
			if proto == "https" {
				if *verbose {
					log.Println("redirecting to control panel")
				}

				origin = controlPanelOrigin
			} else {
				if *verbose {
					log.Println("redirecting to inform endpoint")
				}

				origin = informEndpointOrigin
			}
		}

		if origin == controlPanelOrigin && websocket.IsWebSocketUpgrade(r) {
			wsProxy.ServeHTTP(w, r)
			return
		}

		if *verbose {
			log.Println("proxying to", origin+tail)
		}

		var buf bytes.Buffer
		n, err := buf.ReadFrom(r.Body)
		if err != nil {
			panic(err)
		}

		if *verbose {
			log.Printf("read %d bytes", n)
		}

		req2, err := http.NewRequestWithContext(r.Context(), r.Method, origin+tail, &buf)
		if err != nil {
			panic(err)
		}

		for k, vs := range r.Header {
			for _, v := range vs {
				switch strings.ToLower(k) {
				case "origin":
					if (proto == "" && strings.HasSuffix(v, "://"+r.Host)) || v == proto+"://"+r.Host {
						// only rewrite origin if it's the same host
						v = origin
					}

				case "referer":
					if u, err := url.Parse(v); err == nil {
						if (proto == "" || u.Scheme == proto) && u.Host == r.Host {
							// only rewrite referrer if it's the same host
							v = origin + u.Path
							if u.RawQuery != "" {
								v += "?" + u.RawQuery
							}
						}
					}
				}

				req2.Header.Add(k, v)
			}
		}

		res2, err := httpClient.Do(req2)
		if err != nil {
			panic(err)
		}

		defer res2.Body.Close()

		for k, vs := range res2.Header {
			for _, v := range vs {
				if strings.ToLower(k) == "location" {
					if u, err := url.Parse(v); err == nil {
						u.Host = r.Host
						v = u.String()
					}
				}

				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(res2.StatusCode)

		n, err = io.Copy(w, res2.Body)
		if err != nil {
			panic(err)
		}

		if *verbose {
			log.Printf("wrote %d bytes", n)
		}
	}))
}
