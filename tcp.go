package main

import (
	"net"
	"net/http"

	"github.com/cloudflare/cloudflared/websocket"
	"github.com/rs/zerolog"
)

type TCPOverWS struct {
	dest string
}

var logger = zerolog.Nop()

func (t *TCPOverWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var hijacker http.Hijacker
	var ok bool
	if hijacker, ok = w.(http.Hijacker); !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	conn, err := net.Dial("tcp", t.dest)
	if err != nil {
		panic(err)
	}

	for k, vs := range websocket.NewResponseHeader(r) {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(http.StatusSwitchingProtocols)

	tunneledConn, _, err := hijacker.Hijack()
	if err != nil {
		panic(err)
	}

	websocket.Stream(
		websocket.NewConn(
			r.Context(),
			tunneledConn,
			&logger,
		),
		conn,
		&logger,
	)
}
