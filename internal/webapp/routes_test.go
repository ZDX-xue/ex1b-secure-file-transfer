package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ex1b/internal/monitor"
	"ex1b/internal/webauth"
)

func TestPortalsKeepSessionsSeparateInOneCookieJar(t *testing.T) {
	const password = "portal-test-password"
	accounts, err := webauth.Open(filepath.Join(t.TempDir(), "accounts.json"), password)
	if err != nil {
		t.Fatal(err)
	}
	admin, ok := accounts.Lookup("admin")
	if !ok {
		t.Fatal("administrator is missing")
	}
	user, err := accounts.Register("alice", password, "normal", nil)
	if err != nil {
		t.Fatal(err)
	}
	adminEntry := portalEntry{origin: "http://localhost:44081", host: "localhost:44081", role: "admin", name: "管理员入口", cookie: "ex1b_web_session_44081"}
	userEntry := portalEntry{origin: "http://localhost:44082", host: "localhost:44082", role: "user", name: "用户入口 1", cookie: "ex1b_web_session_44082"}
	app := &gateway{
		registry: accounts,
		sessions: map[string]*browserSession{
			"admin-token": {user: admin, portalHost: adminEntry.host, csrf: "admin-csrf", expiry: time.Now().Add(time.Hour), cancel: func() {}},
			"user-token":  {user: user, portalHost: userEntry.host, csrf: "user-csrf", expiry: time.Now().Add(time.Hour), cancel: func() {}},
		},
	}
	entries := []portalEntry{adminEntry, userEntry}
	adminRoutes := app.routes(adminEntry, entries)
	userRoutes := app.routes(userEntry, entries)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	addCookie := func(entry portalEntry, token string) {
		t.Helper()
		target, err := url.Parse(entry.origin)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		entry.writeCookie(w, token, 3600)
		jar.SetCookies(target, w.Result().Cookies())
	}
	addCookie(adminEntry, "admin-token")
	addCookie(userEntry, "user-token")

	me := func(handler http.Handler, entry portalEntry, name string) {
		t.Helper()
		r := httptest.NewRequest("GET", entry.origin+"/api/auth/me", nil)
		cookies := jar.Cookies(r.URL)
		if len(cookies) != 2 {
			t.Fatalf("browser does not send both cookies: got %d", len(cookies))
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var result struct{ User webauth.User }
		if err := json.NewDecoder(w.Body).Decode(&result); err != nil || w.Code != http.StatusOK || result.User.Username != name {
			t.Fatalf("%s identity = %v, status %d, decode %v", entry.host, result.User, w.Code, err)
		}
	}
	me(adminRoutes, adminEntry, "admin")
	me(userRoutes, userEntry, "alice")

	cross := httptest.NewRequest("GET", adminEntry.origin+"/api/auth/me", nil)
	cross.AddCookie(&http.Cookie{Name: adminEntry.cookie, Value: "user-token"})
	rejected := httptest.NewRecorder()
	adminRoutes.ServeHTTP(rejected, cross)
	if rejected.Code != http.StatusUnauthorized {
		t.Fatalf("cross-port session status = %d", rejected.Code)
	}

	signOut := httptest.NewRequest("POST", userEntry.origin+"/api/auth/logout", nil)
	signOut.Header.Set("Origin", userEntry.origin)
	signOut.Header.Set("X-CSRF-Token", "user-csrf")
	for _, c := range jar.Cookies(signOut.URL) {
		signOut.AddCookie(c)
	}
	w := httptest.NewRecorder()
	userRoutes.ServeHTTP(w, signOut)
	cookies := w.Result().Cookies()
	if w.Code != http.StatusOK || len(cookies) != 1 || cookies[0].Name != userEntry.cookie || cookies[0].MaxAge != -1 {
		t.Fatalf("logout status = %d, cookies = %v", w.Code, cookies)
	}
	me(adminRoutes, adminEntry, "admin")
}

func TestMonitorHistoryIsAdminOnly(t *testing.T) {
	accounts, err := webauth.Open(filepath.Join(t.TempDir(), "accounts.json"), "portal-test-password")
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := accounts.Lookup("admin")
	user, err := accounts.Register("alice", "portal-test-password", "normal", nil)
	if err != nil {
		t.Fatal(err)
	}
	entry := portalEntry{origin: "http://localhost:44080", host: "localhost:44080", role: "main", cookie: "ex1b_web_session_44080"}
	history, err := monitor.Open("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	history.Record(now.Add(-10*time.Second), monitor.Counters{})
	history.Record(now.Add(-5*time.Second), monitor.Counters{Received: 1 << 20, Online: 2})
	app := &gateway{
		registry: accounts, history: history, sessions: map[string]*browserSession{
			"admin": {user: admin, portalHost: entry.host, expiry: now.Add(time.Hour)},
			"alice": {user: user, portalHost: entry.host, expiry: now.Add(time.Hour)},
		},
	}
	handler := app.routes(entry, []portalEntry{entry})
	for _, tc := range []struct {
		token string
		query string
		want  int
	}{
		{"", "15m", http.StatusUnauthorized},
		{"alice", "15m", http.StatusForbidden},
		{"admin", "2h", http.StatusBadRequest},
		{"admin", "24h", http.StatusOK},
	} {
		req := httptest.NewRequest("GET", entry.origin+"/api/admin/history?range="+tc.query, nil)
		if tc.token != "" {
			req.AddCookie(&http.Cookie{Name: entry.cookie, Value: tc.token})
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s returned %d, want %d", tc.token, tc.query, rec.Code, tc.want)
		}
		if tc.want == http.StatusOK {
			var window monitor.Window
			if err := json.NewDecoder(rec.Body).Decode(&window); err != nil ||
				window.Range != "24h" || len(window.Points) != 1 || window.Totals.Received != 1<<20 {
				t.Fatalf("unexpected samples: %+v, %v", window, err)
			}
		}
	}
}

func TestPortalLoginRoleAndListenerOrigin(t *testing.T) {
	const password = "portal-test-password"
	accounts, err := webauth.Open(filepath.Join(t.TempDir(), "accounts.json"), password)
	if err != nil {
		t.Fatal(err)
	}
	adminEntry := portalEntry{origin: "http://localhost:44081", host: "localhost:44081", role: "admin", name: "管理员入口", cookie: "ex1b_web_session_44081"}
	userEntry := portalEntry{origin: "http://localhost:44082", host: "localhost:44082", role: "user", name: "用户入口 1", cookie: "ex1b_web_session_44082"}
	app := &gateway{registry: accounts}
	entries := []portalEntry{adminEntry, userEntry}
	adminRoutes := app.routes(adminEntry, entries)
	userRoutes := app.routes(userEntry, entries)
	for _, tc := range []struct {
		name    string
		handler http.Handler
		url     string
		origin  string
		body    string
	}{
		{"admin login on user port", userRoutes, userEntry.origin + "/api/auth/login", userEntry.origin, `{"username":"admin","password":"portal-test-password"}`},
		{"registration on admin port", adminRoutes, adminEntry.origin + "/api/auth/register", adminEntry.origin, `{}`},
		{"wrong origin on listener", adminRoutes, adminEntry.origin + "/api/auth/login", userEntry.origin, `{}`},
		{"wrong host on listener", adminRoutes, userEntry.origin + "/api/auth/login", userEntry.origin, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tc.url, strings.NewReader(tc.body))
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d: %s", w.Code, w.Body)
			}
		})
	}
}
