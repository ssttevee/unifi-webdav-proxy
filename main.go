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
	"strings"
	"time"

	"github.com/gorilla/websocket"
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

func proxyToOrigin(httpClient *http.Client, w http.ResponseWriter, r *http.Request, endpoint string, body io.Reader, proto, origin string) error {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, endpoint, body)
	if err != nil {
		return err
	}

	for k, vs := range r.Header {
		for _, v := range vs {
			lower := strings.ToLower(k)
			if strings.HasPrefix(lower, "x-") || lower == "via" {
				continue
			}

			switch lower {
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

			req.Header.Add(k, v)
		}
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	for k, vs := range res.Header {
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

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		return err
	}

	w.WriteHeader(res.StatusCode)

	_, err = buf.WriteTo(w)
	if err != nil {
		return err
	}

	return nil
}

var wsdialer = websocket.Dialer{
	HandshakeTimeout: 45 * time.Second,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
	EnableCompression: true,
}

func RemoveWSHeaders(h http.Header) http.Header {
	clone := h.Clone()
	for k := range clone {
		if strings.HasPrefix(k, "Sec-Websocket-") {
			clone.Del(k)
		}
	}

	clone.Del("upgrade")
	clone.Del("connection")
	clone.Del("origin")
	clone.Del("accept-encoding")

	return clone
}

func WSCopy(dst, src *websocket.Conn) error {
	for {
		t, r, err := src.NextReader()
		if err != nil {
			return fmt.Errorf("failed to get next reader: %w", err)
		}

		w, err := dst.NextWriter(t)
		if err != nil {
			return fmt.Errorf("failed to get next writer: %w", err)
		}

		if _, err := io.Copy(w, r); err != nil {
			return fmt.Errorf("failed to copy: %w", err)
		}

		if err := w.Close(); err != nil {
			return fmt.Errorf("failed to close: %w", err)
		}
	}
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
		} else if shouldRedirect(proto, hostname, port) && (r.Header.Get("X-Unifi-Client-Version") == "" || port != ":8443") {
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
				upstreamURL := *r.URL
				upstreamURL.Scheme = "wss"
				upstreamURL.Host = *target + ":8443"

				upstream, res, err := wsdialer.Dial(upstreamURL.String(), RemoveWSHeaders(r.Header))
				if err != nil {
					l.Println("failed to connect to upstream websocket:", err)
					http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
					return
				}

				defer upstream.Close()

				var upgrader websocket.Upgrader
				downstream, err := upgrader.Upgrade(w, r, RemoveWSHeaders(res.Header))
				if err != nil {
					// connection is already hijacked, so we can't send a response
					l.Println("failed to upgrade connection:", err)
					// http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
					return
				}

				defer downstream.Close()

				done := make(chan time.Time, 2)

				go func() {
					defer func() {
						done <- time.Now()
					}()

					if err := WSCopy(upstream, downstream); err != nil {
						l.Println("failed to copy from downstream to upstream:", err)
					}
				}()

				go func() {
					defer func() {
						done <- time.Now()
					}()

					if err := WSCopy(downstream, upstream); err != nil {
						l.Println("failed to copy from upstream to downstream:", err)
					}
				}()

				<-done
				return
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

		for i := 0; ; {
			if err := proxyToOrigin(httpClient, w, r, origin+tail, &buf, proto, origin); err != nil && !errors.Is(err, context.Canceled) {
				if i < 5 {
					i++
					l.Println("retrying", err)
					continue
				}

				panic(err)
			}

			break
		}
	}))
}
