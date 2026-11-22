package webapp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"ex1b/internal/identity"
	"ex1b/internal/portal"
	"ex1b/internal/service"
	"ex1b/internal/transfer"
	"ex1b/internal/ui"
	"ex1b/internal/webauth"
)

const sessionLife = 8 * time.Hour

func (entry portalEntry) accepts(role string) bool {
	switch entry.role {
	case "main":
		return role == "admin" || role == "normal" || role == "vip"
	case "admin":
		return role == "admin"
	case "user":
		return role == "normal" || role == "vip"
	default:
		return false
	}
}

func (g *gateway) routes(entry portalEntry, entries []portalEntry) http.Handler {
	mux := http.NewServeMux()
	for pattern, asset := range map[string]struct{ path, mime string }{
		"GET /{$}":       {"web/index.html", "text/html; charset=utf-8"},
		"GET /style.css": {"web/style.css", "text/css; charset=utf-8"},
		"GET /app.js":    {"web/app.js", "application/javascript; charset=utf-8"},
	} {
		data, err := portal.Assets.ReadFile(asset.path)
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if err != nil {
				http.Error(w, "页面资源不可用", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", asset.mime)
			_, _ = w.Write(data)
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, http.StatusOK, map[string]bool{"ok": true}) })
	type entryLink struct {
		Role   string `json:"role"`
		Name   string `json:"name"`
		Origin string `json:"origin"`
	}
	links := make([]entryLink, 0, len(entries))
	for _, link := range entries {
		links = append(links, entryLink{Role: link.role, Name: link.name, Origin: link.origin})
	}
	mux.HandleFunc("GET /api/entry", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, struct {
			Role    string      `json:"role"`
			Name    string      `json:"name"`
			Entries []entryLink `json:"entries"`
		}{Role: entry.role, Name: entry.name, Entries: links})
	})
	mux.HandleFunc("POST /api/auth/register", func(w http.ResponseWriter, r *http.Request) {
		if !entry.accepts("normal") {
			fail(w, http.StatusForbidden, "请在用户入口注册")
			return
		}
		g.register(w, r)
	})
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		g.login(w, r, entry)
	})
	requireSession := func(access string, next func(http.ResponseWriter, *http.Request, *browserSession)) http.HandlerFunc {
		return g.authorize(entry, access, next)
	}
	mux.HandleFunc("GET /api/auth/me", requireSession("", func(w http.ResponseWriter, r *http.Request, s *browserSession) {
		g.sessionResponse(w, s)
	}))
	mux.HandleFunc("POST /api/auth/logout", requireSession("", func(w http.ResponseWriter, r *http.Request, s *browserSession) {
		if c, err := r.Cookie(entry.cookie); err == nil {
			g.removeSession(c.Value, entry.host)
		}
		entry.writeCookie(w, "", -1)
		success(w)
	}))
	mux.HandleFunc("POST /api/auth/password", requireSession("", func(w http.ResponseWriter, r *http.Request, s *browserSession) {
		g.changePassword(w, r, s, entry)
	}))
	for _, route := range []string{
		"GET /api/state", "GET /api/files/{id}", "POST /api/upload", "POST /api/download", "POST /api/reconnect",
		"POST /api/tasks/{id}/pause", "POST /api/tasks/{id}/resume",
	} {
		mux.HandleFunc(route, requireSession("user", func(w http.ResponseWriter, r *http.Request, s *browserSession) {
			s.workspace.ServeHTTP(w, r)
		}))
	}
	mux.HandleFunc("GET /api/people", requireSession("user", g.people))
	mux.HandleFunc("POST /api/share", requireSession("user", g.share))
	mux.HandleFunc("GET /api/inbox", requireSession("user", g.messages(false)))
	mux.HandleFunc("GET /api/outbox", requireSession("user", g.messages(true)))
	mux.HandleFunc("GET /api/admin/state", requireSession("admin", func(w http.ResponseWriter, r *http.Request, s *browserSession) {
		respond(w, http.StatusOK, struct {
			Accounts []webauth.User `json:"accounts"`
			service.Snapshot
		}{g.registry.List(), g.service.Snapshot()})
	}))
	mux.HandleFunc("GET /api/admin/history", requireSession("admin", func(w http.ResponseWriter, r *http.Request, _ *browserSession) {
		if g.history == nil {
			fail(w, http.StatusServiceUnavailable, "流量历史尚未就绪")
			return
		}
		window := r.URL.Query().Get("range")
		if window == "" {
			window = "15m"
		}
		data, err := g.history.Window(window, time.Now())
		if err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		respond(w, http.StatusOK, data)
	}))
	mux.HandleFunc("POST /api/admin/admission", requireSession("admin", func(w http.ResponseWriter, r *http.Request, s *browserSession) {
		var request struct {
			Accepting *bool `json:"accepting"`
		}
		if !readJSON(w, r, &request) {
			return
		}
		if request.Accepting == nil {
			fail(w, http.StatusBadRequest, "请选择接入状态")
			return
		}
		g.service.SetAccepting(*request.Accepting)
		success(w)
	}))
	mux.HandleFunc("POST /api/admin/users/{username}/state", requireSession("admin", g.userState))
	mux.HandleFunc("POST /api/admin/users/{username}/password", requireSession("admin", g.resetUserPassword))
	mux.HandleFunc("POST /api/admin/users/{username}/delete", requireSession("admin", g.deleteUser))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Host != entry.host || (r.Method == http.MethodPost && r.Header.Get("Origin") != entry.origin) {
			fail(w, http.StatusForbidden, "页面地址或操作来源不匹配")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (g *gateway) authorize(entry portalEntry, access string, next func(http.ResponseWriter, *http.Request, *browserSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie(entry.cookie)
		if err != nil {
			fail(w, http.StatusUnauthorized, "请先登录")
			return
		}
		g.mu.Lock()
		s := g.sessions[token.Value]
		g.mu.Unlock()
		if s == nil || s.portalHost != entry.host || time.Now().After(s.expiry) {
			fail(w, http.StatusUnauthorized, "登录已过期，请重新登录")
			return
		}
		user, ok := g.registry.Lookup(s.user.Username)
		if !ok || !user.Enabled {
			g.removeSession(token.Value, entry.host)
			fail(w, http.StatusUnauthorized, "账号已停用或会话已失效")
			return
		}
		if !entry.accepts(user.Role) || access == "admin" && user.Role != "admin" || access == "user" && user.Role == "admin" {
			fail(w, http.StatusForbidden, "该账号无此操作权限")
			return
		}
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(s.csrf), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
			fail(w, http.StatusForbidden, "会话安全校验失败，请刷新后重试")
			return
		}
		next(w, r, s)
	}
}

func (g *gateway) attempt(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.After(g.window) {
		g.window = now.Add(time.Minute)
		g.attempts = make(map[string]int)
	}
	if len(g.attempts) >= 1024 && g.attempts[host] == 0 || g.attempts[host] >= 30 {
		return false
	}
	g.attempts[host]++
	return true
}

func (g *gateway) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !g.attempt(r) {
		fail(w, http.StatusTooManyRequests, "操作太频繁，请稍后再试")
		return
	}
	g.accountChanges.Lock()
	defer g.accountChanges.Unlock()
	user, err := g.registry.Register(in.Username, in.Password, in.Role, func(user webauth.User) error {
		user.Enabled = false
		return g.provision(user)
	})
	if err != nil {
		authFailure(w, err)
		return
	}
	if err := g.service.SetUserEnabled(user.Username, true); err != nil {
		_, _ = g.registry.SetEnabled(user.Username, false)
		fail(w, http.StatusInternalServerError, "账号建立，启用证书失败。请由管理员检查")
		return
	}
	respond(w, http.StatusCreated, user)
}

func (g *gateway) login(w http.ResponseWriter, r *http.Request, entry portalEntry) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !g.attempt(r) {
		fail(w, http.StatusTooManyRequests, "操作太频繁，请稍后再试")
		return
	}
	// Serialize publication of a new session with credential resets and deletion.
	g.accountChanges.Lock()
	defer g.accountChanges.Unlock()
	user, err := g.registry.Authenticate(in.Username, in.Password)
	if err != nil {
		authFailure(w, err)
		return
	}
	if !entry.accepts(user.Role) {
		message := "请从管理员入口登录"
		if entry.role == "admin" {
			message = "管理员入口只接受管理员账号"
		}
		fail(w, http.StatusForbidden, message)
		return
	}
	g.signIn(w, r, user, entry)
}

func (g *gateway) signIn(w http.ResponseWriter, r *http.Request, user webauth.User, entry portalEntry) {
	ctx, cancel := context.WithCancel(g.ctx)
	s := &browserSession{user: user, portalHost: entry.host, csrf: randomToken(24), expiry: time.Now().Add(sessionLife), cancel: cancel}
	if user.Role != "admin" {
		key := filepath.Join(g.data, "pki", "user-"+user.Username+".pem")
		engine, err := transfer.New(ctx, identity.ClientConfig{
			Address: g.transport, ServerName: "127.0.0.1", CertFile: key, KeyFile: key, CAFile: g.authority.CAFile(),
		})
		if err != nil {
			cancel()
			fail(w, http.StatusServiceUnavailable, "文件客户端的证书未就绪")
			return
		}
		handler, release, err := ui.NewWorkspace(ctx, filepath.Join(g.data, "downloads", user.Username), engine)
		if err != nil {
			cancel()
			fail(w, http.StatusServiceUnavailable, "文件工作区未就绪")
			return
		}
		s.engine, s.workspace, s.close = engine, handler, release
	}
	key := randomToken(32)
	g.mu.Lock()
	var previous *browserSession
	for id, current := range g.sessions {
		if current.user.Username == user.Username {
			previous = current
			delete(g.sessions, id)
			break
		}
	}
	if len(g.sessions) >= 64 {
		g.mu.Unlock()
		retire(s)
		fail(w, http.StatusServiceUnavailable, "浏览器会话数量达到上限")
		return
	}
	g.sessions[key] = s
	g.mu.Unlock()
	retire(previous)
	if before, err := r.Cookie(entry.cookie); err == nil {
		g.removeSession(before.Value, entry.host)
	}
	entry.writeCookie(w, key, int(sessionLife.Seconds()))
	g.sessionResponse(w, s)
}

func (g *gateway) sessionResponse(w http.ResponseWriter, s *browserSession) {
	respond(w, http.StatusOK, struct {
		User webauth.User `json:"user"`
		CSRF string       `json:"csrf"`
	}{s.user, s.csrf})
}

func (entry portalEntry) writeCookie(w http.ResponseWriter, value string, age int) {
	http.SetCookie(w, &http.Cookie{
		Name: entry.cookie, Value: value, Path: "/", HttpOnly: true,
		Secure: entry.secure, SameSite: http.SameSiteStrictMode, MaxAge: age,
	})
}

func retire(s *browserSession) {
	if s == nil {
		return
	}
	s.cancel()
	if s.engine != nil {
		s.engine.Drop()
	}
	if s.close != nil {
		go s.close()
	}
}

func (g *gateway) removeSession(key string, portalHost string) {
	g.mu.Lock()
	s := g.sessions[key]
	if s == nil || s.portalHost != portalHost {
		g.mu.Unlock()
		return
	}
	delete(g.sessions, key)
	g.mu.Unlock()
	retire(s)
}

func (g *gateway) revoke(username string) {
	var retired []*browserSession
	g.mu.Lock()
	for key, s := range g.sessions {
		if username == "" || s.user.Username == username {
			retired = append(retired, s)
			delete(g.sessions, key)
		}
	}
	g.mu.Unlock()
	for _, s := range retired {
		retire(s)
	}
}

func (g *gateway) expireSessions() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case now := <-tick.C:
			var expired []*browserSession
			g.mu.Lock()
			for key, s := range g.sessions {
				if now.After(s.expiry) {
					expired = append(expired, s)
					delete(g.sessions, key)
				}
			}
			g.mu.Unlock()
			for _, s := range expired {
				retire(s)
			}
		}
	}
}

func (g *gateway) changePassword(w http.ResponseWriter, r *http.Request, s *browserSession, entry portalEntry) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new_password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	g.accountChanges.Lock()
	defer g.accountChanges.Unlock()
	if err := g.registry.ChangePassword(s.user.Username, in.Current, in.New); err != nil {
		authFailure(w, err)
		return
	}
	g.revoke(s.user.Username)
	entry.writeCookie(w, "", -1)
	success(w)
}

func (g *gateway) userState(w http.ResponseWriter, r *http.Request, s *browserSession) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Enabled == nil {
		fail(w, http.StatusBadRequest, "请选择账号状态")
		return
	}
	id := r.PathValue("username")
	g.accountChanges.Lock()
	defer g.accountChanges.Unlock()
	previous, _ := g.registry.Lookup(id)
	user, err := g.registry.SetEnabled(id, *in.Enabled)
	if err != nil {
		authFailure(w, err)
		return
	}
	if err := g.service.SetUserEnabled(id, *in.Enabled); err != nil {
		_, _ = g.registry.SetEnabled(id, previous.Enabled)
		fail(w, http.StatusServiceUnavailable, "文件服务未能同步账号状态")
		return
	}
	if !*in.Enabled {
		g.revoke(id)
	}
	respond(w, http.StatusOK, user)
}

func (g *gateway) resetUserPassword(w http.ResponseWriter, r *http.Request, _ *browserSession) {
	var in struct {
		New string `json:"new_password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	id := r.PathValue("username")
	g.accountChanges.Lock()
	defer g.accountChanges.Unlock()
	if err := g.registry.ResetPassword(id, in.New); err != nil {
		authFailure(w, err)
		return
	}
	g.revoke(id)
	g.service.PasswordReset(id)
	success(w)
}

func (g *gateway) deleteUser(w http.ResponseWriter, r *http.Request, _ *browserSession) {
	var in struct {
		Confirm string `json:"confirm_username"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	id := r.PathValue("username")
	if in.Confirm != id {
		fail(w, http.StatusBadRequest, "确认输入的账号名与目标账号不一致")
		return
	}
	g.accountChanges.Lock()
	defer g.accountChanges.Unlock()
	if err := g.registry.Delete(id); err != nil {
		authFailure(w, err)
		return
	}
	g.revoke(id)
	g.service.RemoveUser(id)
	success(w)
}

func (g *gateway) people(w http.ResponseWriter, r *http.Request, s *browserSession) {
	list := make([]webauth.User, 0)
	for _, user := range g.registry.List() {
		if user.Enabled && user.Role != "admin" && user.Username != s.user.Username {
			list = append(list, user)
		}
	}
	respond(w, http.StatusOK, list)
}

func (g *gateway) share(w http.ResponseWriter, r *http.Request, s *browserSession) {
	var in struct {
		Recipient string `json:"recipient"`
		Name      string `json:"name"`
		Message   string `json:"message"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	id, err := s.engine.Send(r.Context(), in.Recipient, in.Name, in.Message)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	respond(w, http.StatusCreated, map[string]string{"id": id})
}

func (g *gateway) messages(outbox bool) func(http.ResponseWriter, *http.Request, *browserSession) {
	return func(w http.ResponseWriter, r *http.Request, s *browserSession) {
		messages, err := s.engine.Shares(r.Context(), outbox)
		if err != nil {
			fail(w, http.StatusServiceUnavailable, "中转连接暂不可用")
			return
		}
		respond(w, http.StatusOK, messages)
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "请使用 JSON 表单")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(new(any)) != io.EOF {
		fail(w, http.StatusBadRequest, "请求格式无效")
		return false
	}
	return true
}

func authFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webauth.ErrCredentials):
		fail(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, webauth.ErrExists):
		fail(w, http.StatusConflict, err.Error())
	case errors.Is(err, webauth.ErrBusy), errors.Is(err, webauth.ErrCapacity):
		fail(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, webauth.ErrUsername), errors.Is(err, webauth.ErrPassword), errors.Is(err, webauth.ErrRole),
		errors.Is(err, webauth.ErrAdmin), errors.Is(err, webauth.ErrAccount):
		fail(w, http.StatusBadRequest, err.Error())
	default:
		fail(w, http.StatusInternalServerError, "账号操作暂时失败")
	}
}

func respond(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func success(w http.ResponseWriter) { respond(w, http.StatusOK, map[string]bool{"ok": true}) }
func fail(w http.ResponseWriter, status int, reason string) {
	respond(w, status, map[string]string{"error": reason})
}
