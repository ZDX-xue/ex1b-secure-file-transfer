// Package webapp hosts the authenticated browser gateway for the file protocol.
package webapp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ex1b/internal/identity"
	"ex1b/internal/service"
	"ex1b/internal/transfer"
	"ex1b/internal/webauth"
)

type Options struct {
	Listen            string
	Origin            string
	Data              string
	AdminPasswordFile string
	Ready             func(origin, caFile, passwordFile string)
}

type gateway struct {
	ctx       context.Context
	data      string
	origin    string
	host      string
	secure    bool
	authority *identity.Authority
	registry  *webauth.Store
	service   *service.Server
	transport string

	mu             sync.Mutex
	accountChanges sync.Mutex
	sessions       map[string]*browserSession
	attempts       map[string]int
	window         time.Time
}

type browserSession struct {
	user      webauth.User
	csrf      string
	expiry    time.Time
	engine    *transfer.Engine
	workspace http.Handler
	cancel    context.CancelFunc
	close     func()
}

func Run(ctx context.Context, options Options) error {
	origin, err := url.Parse(options.Origin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" {
		return errors.New("Web origin 必须是完整的协议、主机名和端口")
	}
	if _, _, err := net.SplitHostPort(origin.Host); err != nil {
		return errors.New("Web origin 需要明确端口")
	}
	listenHost, _, err := net.SplitHostPort(options.Listen)
	if err != nil {
		return err
	}
	if origin.Scheme != "https" {
		ip := net.ParseIP(listenHost)
		host := origin.Hostname()
		if origin.Scheme != "http" || ip == nil || !ip.IsLoopback() ||
			(host != "localhost" && !net.ParseIP(host).IsLoopback()) {
			return errors.New("局域网访问需要 HTTPS；HTTP 仅支持本机回环")
		}
	}
	data, err := filepath.Abs(options.Data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(data, 0700); err != nil {
		return err
	}
	passwordFile, password, err := initialPassword(data, options.AdminPasswordFile)
	if err != nil {
		return err
	}
	registry, err := webauth.Open(filepath.Join(data, "accounts.json"), password)
	if err != nil {
		return err
	}
	authority, err := identity.OpenAuthority(filepath.Join(data, "pki"))
	if err != nil {
		return err
	}
	transportCert, _, err := authority.Server("file-service", "127.0.0.1")
	if err != nil {
		return err
	}
	var webCert string
	if origin.Scheme == "https" {
		webCert, _, err = authority.Server("web-gateway", origin.Hostname(), "localhost", "127.0.0.1")
		if err != nil {
			return err
		}
	}
	fileListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer fileListener.Close()
	webListener, err := net.Listen("tcp", options.Listen)
	if err != nil {
		return err
	}
	defer webListener.Close()
	svc, err := service.NewWeb(identity.ServerConfig{
		Listen: fileListener.Addr().String(), CertFile: transportCert, KeyFile: transportCert, CAFile: authority.CAFile(),
		MaxConnections: 24, MaxFileBytes: 64 << 20, AuditFile: filepath.Join(data, "audit.jsonl"),
	}, filepath.Join(data, "shares.json"))
	if err != nil {
		return err
	}
	defer svc.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	app := &gateway{
		ctx: runCtx, data: data, origin: origin.String(), host: origin.Host, secure: origin.Scheme == "https", authority: authority,
		registry: registry, service: svc, transport: fileListener.Addr().String(), sessions: make(map[string]*browserSession),
	}
	for _, user := range registry.List() {
		if user.Role != "admin" {
			if err := app.provision(user); err != nil {
				return fmt.Errorf("恢复用户 %s 的文件身份: %w", user.Username, err)
			}
		}
	}
	server := &http.Server{
		Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	stop := context.AfterFunc(runCtx, func() { _ = server.Close() })
	defer stop()
	ended := make(chan error, 2)
	go app.expireSessions()
	go func() { ended <- svc.Serve(runCtx, fileListener) }()
	go func() {
		if webCert != "" {
			ended <- server.ServeTLS(webListener, webCert, webCert)
		} else {
			ended <- server.Serve(webListener)
		}
	}()
	if options.Ready != nil {
		options.Ready(options.Origin, authority.CAFile(), passwordFile)
	}
	first := <-ended
	cancel()
	second := <-ended
	app.revoke("")
	if errors.Is(first, http.ErrServerClosed) {
		first = nil
	}
	if errors.Is(second, http.ErrServerClosed) {
		second = nil
	}
	return errors.Join(first, second)
}

func initialPassword(data, explicit string) (path, password string, err error) {
	path = explicit
	if path == "" {
		path = filepath.Join(data, "admin-password.txt")
	}
	accountFile := filepath.Join(data, "accounts.json")
	if _, err = os.Stat(accountFile); err == nil {
		return path, "", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	file, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && explicit == "" {
		password = randomToken(15)
		err = os.WriteFile(path, []byte(password+"\n"), 0600)
		return path, password, err
	}
	if err != nil {
		return "", "", err
	}
	return path, strings.TrimSpace(string(file)), nil
}

func randomToken(bytes int) string {
	raw := make([]byte, bytes)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

func (g *gateway) provision(user webauth.User) error {
	_, cert, err := g.authority.Client(user.Username)
	if err != nil {
		return err
	}
	bandwidth := int64(256 << 10)
	if user.Role == "vip" {
		bandwidth = 1 << 20
	}
	return g.service.AddUser(identity.User{
		ID: user.Username, Role: user.Role, Root: filepath.Join(g.data, "files", user.Username),
		BytesPerSecond: bandwidth, QuotaBytes: 128 << 20, Fingerprint: identity.Fingerprint(cert),
	}, 64<<20, user.Enabled)
}
