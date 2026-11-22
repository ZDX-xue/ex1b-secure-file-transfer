// Package webapp hosts the authenticated browser gateway for the file protocol.
package webapp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ex1b/internal/identity"
	"ex1b/internal/monitor"
	"ex1b/internal/service"
	"ex1b/internal/transfer"
	"ex1b/internal/webauth"
)

type Options struct {
	Listen            string
	Origin            string
	AdminPort         int
	UserPorts         string
	Data              string
	AdminPasswordFile string
	Ready             func(origins []string, caFile, passwordFile string)
}

type portalEntry struct {
	listen string
	origin string
	host   string
	role   string
	name   string
	cookie string
	secure bool
}

type gateway struct {
	ctx       context.Context
	data      string
	authority *identity.Authority
	registry  *webauth.Store
	service   *service.Server
	history   *monitor.History
	transport string

	mu             sync.Mutex
	accountChanges sync.Mutex
	sessions       map[string]*browserSession
	attempts       map[string]int
	window         time.Time
}

type browserSession struct {
	user       webauth.User
	portalHost string
	csrf       string
	expiry     time.Time
	engine     *transfer.Engine
	workspace  http.Handler
	cancel     context.CancelFunc
	close      func()
}

func portals(options Options) ([]portalEntry, error) {
	origin, err := url.Parse(options.Origin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" {
		return nil, errors.New("Web origin 必须是完整的协议、主机名和端口")
	}
	originPort, err := strconv.Atoi(origin.Port())
	if err != nil || originPort < 1 || originPort > 65535 || strconv.Itoa(originPort) != origin.Port() {
		return nil, errors.New("Web origin 需要明确的数字端口")
	}
	listenHost, listenPort, err := net.SplitHostPort(options.Listen)
	if err != nil {
		return nil, err
	}
	primaryListenPort, err := strconv.Atoi(listenPort)
	if err != nil || primaryListenPort < 1 || primaryListenPort > 65535 {
		return nil, errors.New("Web 监听地址需要明确的数字端口")
	}
	if origin.Scheme != "https" {
		ip := net.ParseIP(listenHost)
		host := origin.Hostname()
		if origin.Scheme != "http" || ip == nil || !ip.IsLoopback() ||
			(host != "localhost" && !net.ParseIP(host).IsLoopback()) {
			return nil, errors.New("局域网访问需要 HTTPS；HTTP 仅支持本机回环")
		}
	}
	entries := []portalEntry{{
		listen: options.Listen, origin: origin.String(), host: origin.Host, role: "main", name: "服务总入口",
		cookie: "ex1b_web_session_" + origin.Port(), secure: origin.Scheme == "https",
	}}
	used := map[int]bool{originPort: true, primaryListenPort: true}
	add := func(number int, role, name string) error {
		if number < 1 || number > 65535 {
			return errors.New("登录入口端口必须在 1–65535 之间")
		}
		if used[number] {
			return fmt.Errorf("登录入口端口 %d 重复", number)
		}
		used[number] = true
		port := strconv.Itoa(number)
		alias := *origin
		alias.Host = net.JoinHostPort(origin.Hostname(), port)
		entries = append(entries, portalEntry{
			listen: net.JoinHostPort(listenHost, port), origin: alias.String(), host: alias.Host, role: role, name: name,
			cookie: "ex1b_web_session_" + port, secure: origin.Scheme == "https",
		})
		return nil
	}
	if options.AdminPort != 0 {
		if err := add(options.AdminPort, "admin", "管理员入口"); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(options.UserPorts) != "" {
		specs := strings.Split(options.UserPorts, ",")
		if len(specs) > 8 {
			return nil, errors.New("最多配置 8 个用户登录入口")
		}
		for i, value := range specs {
			port, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return nil, errors.New("用户入口应填写以逗号分隔的数字端口")
			}
			if err := add(port, "user", fmt.Sprintf("用户入口 %d", i+1)); err != nil {
				return nil, err
			}
		}
	}
	return entries, nil
}

func Run(ctx context.Context, options Options) error {
	entries, err := portals(options)
	if err != nil {
		return err
	}
	webListeners := make([]net.Listener, 0, len(entries))
	defer func() {
		for _, listener := range webListeners {
			_ = listener.Close()
		}
	}()
	for _, entry := range entries {
		listener, err := net.Listen("tcp", entry.listen)
		if err != nil {
			return fmt.Errorf("%s（%s）无法启动: %w", entry.name, entry.listen, err)
		}
		webListeners = append(webListeners, listener)
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
	if entries[0].secure {
		origin, _ := url.Parse(entries[0].origin)
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
	svc, err := service.NewWeb(identity.ServerConfig{
		Listen: fileListener.Addr().String(), CertFile: transportCert, KeyFile: transportCert, CAFile: authority.CAFile(),
		MaxConnections: 24, MaxFileBytes: 64 << 20, AuditFile: filepath.Join(data, "audit.jsonl"),
	}, filepath.Join(data, "shares.json"))
	if err != nil {
		return err
	}
	defer svc.Close()
	history, err := monitor.Open(filepath.Join(data, "traffic-history.json"))
	if err != nil {
		log.Printf("无法加载流量历史，暂时使用内存采样：%v", err)
		history, _ = monitor.Open("")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	app := &gateway{
		ctx: runCtx, data: data, authority: authority,
		registry: registry, service: svc, history: history, transport: fileListener.Addr().String(), sessions: make(map[string]*browserSession),
	}
	for _, user := range registry.List() {
		if user.Role != "admin" {
			if err := app.provision(user); err != nil {
				return fmt.Errorf("恢复用户 %s 的文件身份: %w", user.Username, err)
			}
		}
	}
	ended := make(chan error, len(entries)+1)
	historyDone := make(chan struct{})
	go func() {
		defer close(historyDone)
		app.sampleTraffic(runCtx)
	}()
	go app.expireSessions()
	go func() { ended <- svc.Serve(runCtx, fileListener) }()
	origins := make([]string, 0, len(entries))
	for i, entry := range entries {
		origins = append(origins, entry.origin)
		server := &http.Server{
			Handler: app.routes(entry, entries), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute,
			WriteTimeout: 2 * time.Minute, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		}
		listener := webListeners[i]
		go func() {
			stop := context.AfterFunc(runCtx, func() { _ = server.Close() })
			defer stop()
			if webCert != "" {
				ended <- server.ServeTLS(listener, webCert, webCert)
			} else {
				ended <- server.Serve(listener)
			}
		}()
	}
	if options.Ready != nil {
		options.Ready(origins, authority.CAFile(), passwordFile)
	}
	var failures []error
	for range len(entries) + 1 {
		err := <-ended
		cancel()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			failures = append(failures, err)
		}
	}
	app.revoke("")
	<-historyDone
	return errors.Join(failures...)
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
