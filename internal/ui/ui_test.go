package ui

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testEngine struct {
	drops   atomic.Int32
	uploads atomic.Int32
	started chan struct{}
}

func (e *testEngine) Info(context.Context) (Status, error) { return Status{}, nil }
func (e *testEngine) List(context.Context) ([]File, error) { return nil, nil }
func (e *testEngine) Drop()                                { e.drops.Add(1) }

func (e *testEngine) Upload(ctx context.Context, name, source string, report func(Progress)) error {
	data, err := os.ReadFile(source)
	if err != nil || name != "报告.txt" || string(data) != "sample" {
		return errors.New("unexpected upload")
	}
	if e.uploads.Add(1) == 1 {
		report(Progress{Done: 3, Total: 6})
		close(e.started)
		<-ctx.Done()
		return ctx.Err()
	}
	report(Progress{Done: 6, Total: 6, ResumedAt: 3, SHA256: "verified"})
	return nil
}

func (e *testEngine) Download(context.Context, string, string, func(Progress)) (string, error) {
	return "", errors.New("unexpected download")
}

func testApp(t *testing.T, e *testEngine) *app {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	stage := filepath.Join(dir, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{engine: e, ctx: ctx, host: "127.0.0.1:43952", origin: "http://127.0.0.1:43952", token: "test-token", root: root, stage: stage, saved: dir}
	t.Cleanup(func() {
		cancel()
		a.work.Wait()
		root.Close()
	})
	return a
}

func post(a *app, uri string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, a.origin+uri, nil)
	r.Header.Set("Origin", a.origin)
	r.Header.Set("X-Client-Token", a.token)
	return r
}

func TestLocalOriginGuards(t *testing.T) {
	e := &testEngine{}
	a := testApp(t, e)
	h := a.routes()
	for name, alter := range map[string]func(*http.Request){
		"host":   func(r *http.Request) { r.Host = "unexpected.example" },
		"origin": func(r *http.Request) { r.Header.Set("Origin", "https://unexpected.example") },
		"token":  func(r *http.Request) { r.Header.Del("X-Client-Token") },
	} {
		t.Run(name, func(t *testing.T) {
			r := post(a, "/api/reconnect")
			alter(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || e.drops.Load() != 0 {
				t.Fatalf("status %d, Drop called %d times", w.Code, e.drops.Load())
			}
		})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, post(a, "/api/reconnect"))
	if w.Code != http.StatusAccepted || e.drops.Load() != 1 {
		t.Fatalf("status %d, Drop called %d times", w.Code, e.drops.Load())
	}
}

func TestStagedUploadCanPauseAndResume(t *testing.T) {
	e := &testEngine{started: make(chan struct{})}
	a := testApp(t, e)
	h := a.routes()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	dst, err := form.CreateFormFile("file", "报告.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dst.Write([]byte("sample")); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, a.origin+"/api/upload", &body)
	r.Header.Set("Origin", a.origin)
	r.Header.Set("X-Client-Token", a.token)
	r.Header.Set("Content-Type", form.FormDataContentType())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	select {
	case <-e.started:
	case <-time.After(time.Second):
		t.Fatal("transfer did not start")
	}
	for _, step := range []struct{ action, state string }{{"pause", "paused"}, {"resume", "done"}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, post(a, "/api/tasks/1/"+step.action))
		if w.Code != http.StatusAccepted {
			t.Fatalf("%s: %d %s", step.action, w.Code, w.Body)
		}
		for deadline := time.Now().Add(time.Second); ; {
			a.mu.Lock()
			state := a.find("1").view.State
			a.mu.Unlock()
			if state == step.state {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected %s, got %s", step.state, state)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, a.origin+"/api/state", nil))
	if !strings.Contains(w.Body.String(), `"resumed_at":3`) || !strings.Contains(w.Body.String(), `"sha256":"verified"`) {
		t.Fatalf("resume results absent: %s", w.Body)
	}
	files, err := os.ReadDir(a.stage)
	if err != nil || len(files) != 0 {
		t.Fatalf("staged file was not removed: %v %v", files, err)
	}
}
