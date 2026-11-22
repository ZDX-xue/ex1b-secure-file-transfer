// Package console exposes the server's administrative page on loopback.
package console

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"ex1b/internal/service"
)

//go:embed index.html style.css app.js
var assets embed.FS

func Serve(ctx context.Context, listen string, svc *service.Server, ready func(string)) error {
	host, _, err := net.SplitHostPort(listen)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return errors.New("服务端管理页只能监听本机回环地址")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	address := ln.Addr().String()
	origin := "http://" + address
	token := hex.EncodeToString(secureToken())
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(struct {
			Token string `json:"token"`
			service.Snapshot
		}{token, svc.Snapshot()})
	})
	mux.HandleFunc("POST /api/admission", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Ex1b-Token")), []byte(token)) != 1 ||
			r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "请求来源无效", http.StatusForbidden)
			return
		}
		in := struct {
			Accepting *bool `json:"accepting"`
		}{}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || in.Accepting == nil || dec.Decode(new(any)) != io.EOF {
			http.Error(w, "请求格式无效", http.StatusBadRequest)
			return
		}
		svc.SetAccepting(*in.Accepting)
		w.WriteHeader(http.StatusNoContent)
	})
	for path, file := range map[string]string{"/": "index.html", "/style.css": "style.css", "/app.js": "app.js"} {
		body, err := assets.ReadFile(file)
		if err != nil {
			return err
		}
		mime := map[string]string{"index.html": "text/html", "style.css": "text/css", "app.js": "application/javascript"}[file]
		if path == "/" {
			path = "/{$}"
		}
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", mime+"; charset=utf-8")
			_, _ = w.Write(body)
		})
	}
	server := &http.Server{
		ReadHeaderTimeout: 4 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 8 * time.Second,
		IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8 << 10,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != address {
				http.Error(w, "仅接受本机访问", http.StatusForbidden)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
			mux.ServeHTTP(w, r)
		}),
	}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	if ready != nil {
		ready(origin)
	}
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("服务端管理页: %w", err)
	}
	return nil
}

func secureToken() []byte {
	token := make([]byte, 32)
	// crypto/rand.Read fills the slice or fails the process in supported Go.
	_, _ = rand.Read(token)
	return token
}
