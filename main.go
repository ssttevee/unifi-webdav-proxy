package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/koding/websocketproxy"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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
	target := flag.String("t", "localhost", "target controller address or hostname")
	basedir := flag.String("b", "/var/lib/unifi", "unifi base directory")
	mock := flag.String("m", "", "mock origin")
	verbose := flag.Bool("v", false, "verbose")
	ssh := flag.Bool("s", false, "enable ssh")
	flag.Parse()

	if *verbose {
		logger = zerolog.New(os.Stdout)
	}

	controlPanelOrigin := "https://" + *target + ":8443"
	informEndpointOrigin := "http://" + *target + ":8080"

	cfg := tls.Config{InsecureSkipVerify: true}

	wsProxy := websocketproxy.NewProxy(&url.URL{
		Scheme: "wss",
		Host:   *target + ":8443",
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

	webdav := NewUnifiWebDAV(*basedir, ace)

	var sshProxy *TCPOverWS
	if *ssh {
		sshProxy = &TCPOverWS{
			dest: "localhost:22",
		}
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
			webdav.ServeHTTP(w, r)
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

			if origin == "" {
				origin = controlPanelOrigin
			}
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
			if sshProxy != nil && r.URL.Path == "/" {
				// assume this is always from `cloudflared access ssh`
				if *verbose {
					log.Println("proxying ssh connection")
				}

				sshProxy.ServeHTTP(w, r)

				if *verbose {
					log.Println("ssh connection closed")
				}
			} else {
				wsProxy.ServeHTTP(w, r)
			}

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
