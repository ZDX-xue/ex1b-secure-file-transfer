// Package ui exposes a browser interface bound to the local client only.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxFileSize = 64 << 20
	maxActive   = 16
	maxRows     = 64
	maxStaging  = 4
)

//go:embed web/index.html web/style.css web/app.js
var assets embed.FS

type Engine interface {
	Info(ctx context.Context) (Status, error)
	List(ctx context.Context) ([]File, error)
	Upload(ctx context.Context, name, sourcePath string, progress func(Progress)) error
	Download(ctx context.Context, name, dir string, progress func(Progress)) (string, error)
	Drop()
}

type Status struct {
	User              string `json:"user"`
	Role              string `json:"role"`
	Session           string `json:"session"`
	Rate              int64  `json:"rate"`
	TLS               string `json:"tls"`
	ServerFingerprint string `json:"server_fingerprint,omitempty"`
	ClientFingerprint string `json:"client_fingerprint,omitempty"`
}

type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Progress struct {
	Done      int64  `json:"done"`
	Total     int64  `json:"total"`
	ResumedAt int64  `json:"resumed_at"`
	SHA256    string `json:"sha256"`
}

type taskView struct {
	ID        uint64 `json:"id"`
	Name      string `json:"name"`
	Direction string `json:"direction"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	Rate      int64  `json:"rate"`
	Saved     bool   `json:"saved,omitempty"`
	Progress
}

type task struct {
	view       taskView
	sourcePath string
	shareID    string
	savedPath  string
	cancel     context.CancelFunc
	lastBytes  int64
	lastSample time.Time
}

type snapshot struct {
	Status  *Status    `json:"status"`
	Problem string     `json:"problem,omitempty"`
	Files   []File     `json:"files"`
	Tasks   []taskView `json:"tasks"`
}

type app struct {
	engine Engine
	ctx    context.Context
	host   string
	origin string
	token  string
	stage  string
	saved  string
	root   *os.Root
	index  string
	mu     sync.Mutex
	work   sync.WaitGroup
	closed bool
	seq    uint64
	slots  int
	tasks  []*task
	remote snapshot
	update chan struct{}
}

// NewWorkspace runs the transfer queue behind a caller-authenticated gateway.
// The gateway is responsible for session authentication, Host and CSRF checks.
func NewWorkspace(ctx context.Context, downloads string, engine Engine) (http.Handler, func(), error) {
	dir, err := filepath.Abs(downloads)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	stage, err := os.MkdirTemp(dir, ".ex1b-uploads-")
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	a := &app{engine: engine, ctx: runCtx, stage: stage, saved: dir, root: root, update: make(chan struct{}, 1)}
	a.work.Add(1)
	go a.refresh()
	var once sync.Once
	closeWorkspace := func() {
		once.Do(func() {
			a.mu.Lock()
			a.closed = true
			a.mu.Unlock()
			cancel()
			engine.Drop()
			a.work.Wait()
			_ = root.Close()
			_ = os.RemoveAll(stage)
		})
	}
	return a.routes(), closeWorkspace, nil
}

// Serve starts a local-only browser interface with a capability for mutations.
func Serve(ctx context.Context, listen, downloads string, engine Engine, ready func(string)) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("客户端界面必须绑定到本机回环 IP")
	}
	dir, err := filepath.Abs(downloads)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	stage, err := os.MkdirTemp(dir, ".ex1b-uploads-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	index, err := assets.ReadFile("web/index.html")
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	address := listener.Addr().String()
	a := &app{
		engine: engine, ctx: runCtx, host: address, origin: "http://" + address,
		token: hex.EncodeToString(token), stage: stage, saved: dir, root: root,
		update: make(chan struct{}, 1),
	}
	a.index = strings.Replace(string(index), "CLIENT_TOKEN", a.token, 1)
	server := &http.Server{
		Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	a.work.Add(1)
	go a.refresh()
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	if ready != nil {
		ready(a.origin)
	}
	select {
	case <-ctx.Done():
		err = nil
	case err = <-result:
	}
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	cancel()
	shutdown, done := context.WithTimeout(context.Background(), 4*time.Second)
	defer done()
	if server.Shutdown(shutdown) != nil {
		server.Close()
	}
	a.work.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, a.index)
	})
	mux.HandleFunc("GET /style.css", a.static("web/style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /app.js", a.static("web/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("GET /api/files/{id}", a.serveDownload)
	mux.HandleFunc("POST /api/upload", a.upload)
	mux.HandleFunc("POST /api/download", a.download)
	mux.HandleFunc("POST /api/tasks/{id}/pause", a.pause)
	mux.HandleFunc("POST /api/tasks/{id}/resume", a.resume)
	mux.HandleFunc("POST /api/reconnect", func(w http.ResponseWriter, r *http.Request) {
		a.engine.Drop()
		a.triggerRefresh()
		reply(w, http.StatusAccepted, map[string]bool{"ok": true})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if a.host != "" && r.Host != a.host {
			failure(w, http.StatusForbidden, "只接受本机界面地址")
			return
		}
		if a.host != "" && r.Method == http.MethodPost && (r.Header.Get("Origin") != a.origin ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Client-Token")), []byte(a.token)) != 1) {
			failure(w, http.StatusForbidden, "操作来源未通过验证，请在本机界面中重试")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *app) static(name, contentType string) http.HandlerFunc {
	content, err := assets.ReadFile(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			failure(w, http.StatusInternalServerError, "无法读取界面资源")
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(content)
	}
}

func (a *app) refresh() {
	defer a.work.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		a.readRemote()
		select {
		case <-a.ctx.Done():
			return
		case <-a.update:
		case <-tick.C:
		}
	}
}

func (a *app) readRemote() {
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Second)
	defer cancel()
	status, err := a.engine.Info(ctx)
	remote := snapshot{}
	if err == nil {
		remote.Status = &status
		remote.Files, err = a.engine.List(ctx)
	}
	if err != nil {
		remote.Problem = err.Error()
	}
	a.mu.Lock()
	a.remote = remote
	a.mu.Unlock()
}

func (a *app) triggerRefresh() {
	select {
	case a.update <- struct{}{}:
	default:
	}
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("write UI response: %v", err)
	}
}

func failure(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}

func (a *app) state(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	data := a.remote
	data.Tasks = make([]taskView, 0, len(a.tasks))
	for i := len(a.tasks) - 1; i >= 0; i-- {
		data.Tasks = append(data.Tasks, a.tasks[i].view)
	}
	a.mu.Unlock()
	reply(w, http.StatusOK, data)
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && utf8.ValidString(name) &&
		!strings.ContainsAny(name, `/\:`) && strings.IndexFunc(name, unicode.IsControl) < 0
}

func (a *app) upload(w http.ResponseWriter, r *http.Request) {
	if !a.reserveStaging() {
		failure(w, http.StatusTooManyRequests, "本机上传队列已满，请稍后重试")
		return
	}
	defer a.releaseStaging()
	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize+(64<<10))
	form, err := r.MultipartReader()
	if err != nil {
		failure(w, http.StatusBadRequest, "请选择一个文件")
		return
	}
	part, err := form.NextPart()
	if err != nil || part.FormName() != "file" || !validName(part.FileName()) {
		failure(w, http.StatusBadRequest, "文件名或上传格式无效")
		return
	}
	file, err := os.CreateTemp(a.stage, "upload-")
	if err != nil {
		failure(w, http.StatusInsufficientStorage, "无法暂存所选文件")
		return
	}
	defer func() {
		if file != nil {
			os.Remove(file.Name())
		}
	}()
	size, writeErr := io.Copy(file, io.LimitReader(part, maxFileSize+1))
	closeErr := file.Close()
	if size > maxFileSize {
		failure(w, http.StatusRequestEntityTooLarge, "单个上传文件上限为 64 MiB")
		return
	}
	if writeErr != nil || closeErr != nil {
		failure(w, http.StatusBadRequest, "文件未能完整暂存")
		return
	}
	if _, err := form.NextPart(); err != io.EOF {
		failure(w, http.StatusBadRequest, "一次请求只能暂存一个文件")
		return
	}
	id, err := a.enqueue(part.FileName(), "upload", file.Name(), size)
	if err != nil {
		failure(w, http.StatusConflict, err.Error())
		return
	}
	file = nil // The task owns the staged file after it enters the queue.
	reply(w, http.StatusAccepted, map[string]uint64{"id": id})
}

func (a *app) reserveStaging() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.slots >= maxStaging || a.active()+a.slots >= maxActive {
		return false
	}
	a.slots++
	a.work.Add(1)
	return true
}

func (a *app) releaseStaging() {
	a.mu.Lock()
	a.slots--
	a.mu.Unlock()
	a.work.Done()
}

func (a *app) download(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name    string `json:"name"`
		ShareID string `json:"share_id,omitempty"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || !validName(request.Name) || len(request.ShareID) > 64 || decoder.Decode(new(any)) != io.EOF {
		failure(w, http.StatusBadRequest, "文件名无效")
		return
	}
	id, err := a.enqueueTransfer(request.Name, "download", "", request.ShareID, 0)
	if err != nil {
		failure(w, http.StatusConflict, err.Error())
		return
	}
	reply(w, http.StatusAccepted, map[string]uint64{"id": id})
}

// active may only be called while holding the app lock.
func (a *app) active() int {
	count := 0
	for _, transfer := range a.tasks {
		if transfer.view.State != "done" && transfer.view.State != "failed" {
			count++
		}
	}
	return count
}

func (a *app) enqueue(name, direction, source string, size int64) (uint64, error) {
	return a.enqueueTransfer(name, direction, source, "", size)
}

func (a *app) enqueueTransfer(name, direction, source, shareID string, size int64) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.active() >= maxActive {
		return 0, errors.New("当前传输队列已满")
	}
	for _, existing := range a.tasks {
		if existing.view.Name == name && existing.view.Direction == direction &&
			existing.view.State != "failed" && existing.view.State != "done" {
			return 0, errors.New("同名文件已经在传输队列中")
		}
	}
	if len(a.tasks) >= maxRows {
		for i, old := range a.tasks {
			if old.view.State == "done" || old.view.State == "failed" {
				a.tasks = append(a.tasks[:i], a.tasks[i+1:]...)
				break
			}
		}
	}
	a.seq++
	transfer := &task{
		view:       taskView{ID: a.seq, Name: name, Direction: direction, Progress: Progress{Total: size}},
		sourcePath: source,
		shareID:    shareID,
	}
	a.tasks = append(a.tasks, transfer)
	a.start(transfer)
	return a.seq, nil
}

// start must be called while holding the app lock and before shutdown starts.
func (a *app) start(transfer *task) {
	ctx, cancel := context.WithCancel(a.ctx)
	transfer.cancel = cancel
	transfer.view.State = "running"
	transfer.view.Error = ""
	transfer.view.Rate = 0
	transfer.lastSample = time.Now()
	transfer.lastBytes = transfer.view.Done
	name, direction, source, shareID := transfer.view.Name, transfer.view.Direction, transfer.sourcePath, transfer.shareID
	a.work.Add(1)
	go func() {
		defer a.work.Done()
		defer cancel()
		var err error
		var saved string
		progress := func(p Progress) { a.progress(transfer, p) }
		if direction == "upload" {
			err = a.engine.Upload(ctx, name, source, progress)
		} else if shareID != "" {
			receiver, ok := a.engine.(interface {
				DownloadShared(context.Context, string, string, string, func(Progress)) (string, error)
			})
			if ok {
				saved, err = receiver.DownloadShared(ctx, name, shareID, a.saved, progress)
			} else {
				err = errors.New("此客户端没有中转下载功能")
			}
		} else {
			saved, err = a.engine.Download(ctx, name, a.saved, progress)
		}
		a.finish(transfer, saved, err, ctx.Err())
	}()
}

func (a *app) progress(transfer *task, progress Progress) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if progress.ResumedAt > transfer.view.ResumedAt || progress.Done < transfer.lastBytes {
		transfer.lastBytes = progress.Done
		transfer.lastSample = now
		transfer.view.Rate = 0
	}
	if elapsed := now.Sub(transfer.lastSample).Seconds(); elapsed >= 0.22 {
		transfer.view.Rate = int64(float64(progress.Done-transfer.lastBytes) / elapsed)
		transfer.lastBytes = progress.Done
		transfer.lastSample = now
	}
	if transfer.view.ResumedAt > progress.ResumedAt {
		progress.ResumedAt = transfer.view.ResumedAt
	}
	transfer.view.Progress = progress
}

func (a *app) finish(transfer *task, saved string, err, contextErr error) {
	a.mu.Lock()
	if err == nil {
		transfer.view.State = "done"
		transfer.view.Done = transfer.view.Total
	} else if errors.Is(contextErr, context.Canceled) && transfer.view.State == "pausing" {
		transfer.view.State = "paused"
	} else {
		transfer.view.State = "failed"
		transfer.view.Error = err.Error()
	}
	if saved != "" && err == nil {
		path, absErr := filepath.Abs(saved)
		if absErr == nil {
			rel, relErr := filepath.Rel(a.saved, path)
			if relErr == nil && rel != "." && filepath.IsLocal(rel) {
				transfer.savedPath = rel
				transfer.view.Saved = true
			}
		}
	}
	transfer.cancel = nil
	transfer.view.Rate = 0
	if transfer.view.State != "paused" && transfer.sourcePath != "" {
		os.Remove(transfer.sourcePath)
		transfer.sourcePath = ""
	}
	a.mu.Unlock()
	a.triggerRefresh()
}

// find requires the app lock.
func (a *app) find(rawID string) *task {
	id, err := strconv.ParseUint(rawID, 10, 64)
	if err == nil {
		for _, transfer := range a.tasks {
			if transfer.view.ID == id {
				return transfer
			}
		}
	}
	return nil
}

func (a *app) pause(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	transfer := a.find(r.PathValue("id"))
	if transfer == nil || transfer.view.State != "running" || transfer.cancel == nil {
		a.mu.Unlock()
		failure(w, http.StatusConflict, "该任务当前无法暂停")
		return
	}
	transfer.view.State = "pausing"
	transfer.cancel()
	a.mu.Unlock()
	reply(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (a *app) resume(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	transfer := a.find(r.PathValue("id"))
	if a.closed || transfer == nil || transfer.view.State != "paused" {
		a.mu.Unlock()
		failure(w, http.StatusConflict, "该任务当前无法继续")
		return
	}
	a.start(transfer)
	a.mu.Unlock()
	reply(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (a *app) serveDownload(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	transfer := a.find(r.PathValue("id"))
	if transfer == nil || !transfer.view.Saved {
		a.mu.Unlock()
		failure(w, http.StatusNotFound, "找不到已保存的文件")
		return
	}
	path, name := transfer.savedPath, transfer.view.Name
	a.mu.Unlock()
	file, err := a.root.Open(path)
	if err != nil {
		failure(w, http.StatusNotFound, "本机文件已被移走")
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		failure(w, http.StatusNotFound, "找不到本机文件")
		return
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, stat.ModTime(), file)
}
