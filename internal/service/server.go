// Package service serves authenticated EX1B sessions and owns their audit trail.
package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ex1b/internal/identity"
	"ex1b/internal/storage"
	"ex1b/internal/wire"
)

const maxRequests = 8

type account struct {
	identity.User
	storage *storage.Store
	rate    *limiter
	enabled atomic.Bool
	maxFile int64
}

type SessionView struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	Role     string    `json:"role"`
	Peer     string    `json:"peer"`
	Rate     int64     `json:"rate"`
	Since    time.Time `json:"since"`
	Received int64     `json:"received"`
	Sent     int64     `json:"sent"`
	Requests uint64    `json:"requests"`
	Incoming int       `json:"incoming"`
	Outgoing int       `json:"outgoing"`
}

type Event struct {
	Time      time.Time `json:"time"`
	User      string    `json:"user"`
	Session   string    `json:"session"`
	Action    string    `json:"action"`
	Name      string    `json:"name,omitempty"`
	Status    string    `json:"status"`
	Offset    int64     `json:"offset,omitempty"`
	Recipient string    `json:"recipient,omitempty"`
	ShareID   string    `json:"share_id,omitempty"`
}

type Snapshot struct {
	Address   string        `json:"address"`
	Accepting bool          `json:"accepting"`
	Capacity  int           `json:"capacity"`
	Users     []UserView    `json:"users"`
	Sessions  []SessionView `json:"sessions"`
	Events    []Event       `json:"events"`
	Traffic   Traffic       `json:"traffic"`
}

type Traffic struct {
	Received int64 `json:"received"`
	Sent     int64 `json:"sent"`
	Incoming int   `json:"incoming"`
	Outgoing int   `json:"outgoing"`
	Shared   int   `json:"shared"`
}

type UserView struct {
	ID      string `json:"id"`
	Role    string `json:"role"`
	Rate    int64  `json:"rate"`
	Quota   int64  `json:"quota"`
	Enabled bool   `json:"enabled"`
}

type activeSession struct {
	SessionView
	conn   net.Conn
	cancel context.CancelFunc
}

type Server struct {
	tls       *tls.Config
	capacity  int
	slots     chan struct{}
	sequence  atomic.Uint64
	accepting atomic.Bool
	logger    *log.Logger
	audit     io.WriteCloser

	mu       sync.Mutex
	address  string
	accounts map[string]*account
	byID     map[string]*account
	sessions map[string]*activeSession
	events   []Event
	traffic  Traffic
	shares   *shareStore
	closed   bool
}

func New(cfg identity.ServerConfig) (*Server, error) {
	secure, err := cfg.TLS()
	if err != nil {
		return nil, err
	}
	s := &Server{
		tls: secure, accounts: make(map[string]*account), capacity: cfg.MaxConnections,
		slots: make(chan struct{}, cfg.MaxConnections), sessions: make(map[string]*activeSession),
		byID:   make(map[string]*account),
		logger: log.New(os.Stderr, "", 0),
	}
	s.accepting.Store(true)
	for _, user := range cfg.Users {
		if err := s.AddUser(user, cfg.MaxFileBytes, true); err != nil {
			s.Close()
			return nil, fmt.Errorf("初始化 %s 的数据目录: %w", user.ID, err)
		}
	}
	if cfg.AuditFile != "" {
		events, err := loadAuditTail(cfg.AuditFile)
		if err != nil {
			s.logger.Printf("读取最近审计记录: %v", err)
		}
		s.events = events
		audit, err := os.OpenFile(cfg.AuditFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("打开审计日志: %w", err)
		}
		s.audit = audit
		s.logger.SetOutput(audit)
	}
	return s, nil
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, session := range s.sessions {
		session.cancel()
		_ = session.conn.Close()
	}
	for _, user := range s.accounts {
		_ = user.storage.Close()
	}
	if s.audit != nil {
		_ = s.audit.Close()
	}
}

func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Snapshot{
		Address: s.address, Accepting: s.accepting.Load(), Capacity: s.capacity,
		Users: make([]UserView, 0, len(s.byID)), Sessions: make([]SessionView, 0, len(s.sessions)),
		Events:  append([]Event{}, s.events...),
		Traffic: s.traffic,
	}
	for _, account := range s.byID {
		out.Users = append(out.Users, UserView{
			ID: account.ID, Role: account.Role, Rate: account.BytesPerSecond,
			Quota: account.QuotaBytes, Enabled: account.enabled.Load(),
		})
	}
	sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].ID < out.Users[j].ID })
	for _, session := range s.sessions {
		out.Sessions = append(out.Sessions, session.SessionView)
	}
	if s.shares != nil {
		out.Traffic.Shared = s.shares.count()
	}
	return out
}

// TrafficSnapshot reads the live counters without copying session or audit history.
func (s *Server) TrafficSnapshot() (Traffic, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.traffic, len(s.sessions)
}

func (s *Server) SetAccepting(value bool) {
	s.accepting.Store(value)
	status := "已暂停新连接"
	if value {
		status = "已开放新连接"
	}
	s.record(Event{User: "本机管理员", Action: "admission", Status: status})
}

func (s *Server) record(event Event) {
	event.Time = time.Now()
	s.mu.Lock()
	s.events = appendAuditEvent(s.events, event)
	s.mu.Unlock()
	data, _ := json.Marshal(event)
	s.logger.Print(string(data))
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	s.mu.Lock()
	s.address = listener.Addr().String()
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !s.accepting.Load() {
			_ = conn.Close()
			continue
		}
		select {
		case s.slots <- struct{}{}:
			workers.Go(func() {
				defer func() { <-s.slots }()
				s.handleSession(ctx, conn)
			})
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) handleSession(parent context.Context, raw net.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer raw.Close()
	after := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer after()
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 25 * time.Second, Interval: 10 * time.Second, Count: 3})
	}
	conn := tls.Server(raw, s.tls)
	timeout, stop := context.WithTimeout(ctx, 5*time.Second)
	err := conn.HandshakeContext(timeout)
	stop()
	if err != nil {
		s.record(Event{Action: "handshake", Status: "拒绝或握手失败"})
		return
	}
	id := fmt.Sprintf("S%04d", s.sequence.Add(1))
	tlsState := conn.ConnectionState()
	cert := tlsState.PeerCertificates[0]
	s.mu.Lock()
	user := s.accounts[identity.Fingerprint(cert)]
	if s.closed || user == nil || !user.enabled.Load() {
		s.mu.Unlock()
		s.record(Event{Action: "handshake", Status: "证书对应账号未启用"})
		return
	}
	view := &activeSession{
		SessionView: SessionView{ID: id, User: user.ID, Role: user.Role, Rate: user.BytesPerSecond, Peer: raw.RemoteAddr().String(), Since: time.Now()},
		conn:        raw, cancel: cancel,
	}
	s.sessions[id] = view
	s.mu.Unlock()
	s.record(Event{User: user.ID, Session: id, Action: "connect", Status: "mTLS 已验证"})
	defer func() {
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
		s.record(Event{User: user.ID, Session: id, Action: "disconnect", Status: "连接已关闭"})
	}()

	var jobs sync.WaitGroup
	defer jobs.Wait()
	defer cancel()
	var writeMu sync.Mutex
	jobSlots := make(chan struct{}, maxRequests)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		req, err := wire.Read(conn)
		if err != nil {
			var netErr net.Error
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !(errors.As(err, &netErr) && netErr.Timeout()) && ctx.Err() == nil {
				s.record(Event{User: user.ID, Session: id, Action: "frame", Status: "连接结束或报文无效"})
			}
			return
		}
		select {
		case jobSlots <- struct{}{}:
			jobs.Go(func() {
				defer func() { <-jobSlots }()
				if req.Kind == "put_chunk" || req.Kind == "get_chunk" {
					s.flow(view, req.Kind, 1)
					defer s.flow(view, req.Kind, -1)
				}
				resp, countIn := s.run(ctx, user, id, req)
				if countIn != 0 {
					s.mu.Lock()
					view.Received += countIn
					s.traffic.Received += countIn
					s.mu.Unlock()
				}
				writeMu.Lock()
				defer writeMu.Unlock()
				if ctx.Err() != nil {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := wire.Write(conn, resp); err != nil {
					cancel()
					return
				}
				s.mu.Lock()
				view.Requests++
				if req.Kind == "get_chunk" {
					view.Sent += int64(len(resp.Body))
					s.traffic.Sent += int64(len(resp.Body))
				}
				s.mu.Unlock()
			})
		default:
			s.record(Event{User: user.ID, Session: id, Action: "limit", Status: "会话请求达到上限"})
			return
		}
	}
}

func (s *Server) flow(session *activeSession, kind string, delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == "put_chunk" {
		session.Incoming += delta
		s.traffic.Incoming += delta
	} else {
		session.Outgoing += delta
		s.traffic.Outgoing += delta
	}
}

func (s *Server) run(ctx context.Context, user *account, session string, req wire.Frame) (wire.Frame, int64) {
	reply := wire.Frame{Header: wire.Header{ID: req.ID, Kind: req.Kind + "_reply"}}
	var err error
	var received int64
	if !user.enabled.Load() {
		err = errors.New("账号已停用")
	} else if req.Kind != "put_chunk" && len(req.Body) != 0 {
		err = errors.New("此请求不接受数据块")
	} else {
		switch req.Kind {
		case "ping", "info":
			reply.User, reply.Role, reply.Session = user.ID, user.Role, session
			reply.Rate, reply.TLS = user.BytesPerSecond, "TLS 1.3 · 双向验证"
		case "list":
			var files []storage.File
			files, err = user.storage.List()
			if err == nil {
				if files == nil {
					files = []storage.File{}
				}
				reply.Body, err = json.Marshal(files)
			}
		case "put_begin":
			reply.Offset, reply.Done, err = user.storage.Begin(req.Name, req.Size, req.SHA256)
		case "put_chunk":
			if len(req.Body) == 0 || len(req.Body) > wire.ChunkSize {
				err = errors.New("上传分块大小无效")
				break
			}
			if err = user.rate.Wait(ctx, len(req.Body)); err == nil {
				reply.Offset, err = user.storage.Write(req.Name, req.Size, req.SHA256, req.Offset, req.Body)
				if err == nil {
					received = int64(len(req.Body))
				}
			}
		case "put_finish":
			err = user.storage.Finish(req.Name, req.Size, req.SHA256)
			reply.Done = err == nil
		case "get_begin", "get_chunk", "get_finish":
			err = s.download(ctx, user, req, &reply)
		case "share_send":
			reply.ShareID, err = s.send(user, req.Recipient, req.Name, req.Message)
		case "share_inbox", "share_outbox":
			reply.Body, err = s.mailbox(user.ID, req.Kind == "share_outbox")
		default:
			err = errors.New("请求类型不受支持")
			reply.Kind = "error_reply"
		}
	}
	if err != nil {
		reply.Body = nil
		reply.Error = publicError(err)
	}
	switch req.Kind {
	case "put_begin", "put_finish", "get_begin", "get_finish", "share_send":
		name := req.Name
		if reply.Name != "" {
			name = reply.Name
		}
		if storage.ValidateName(name) != nil {
			name = ""
		}
		status := reply.Error
		if status == "" {
			status = transferAuditStatus(req.Kind, name, reply.Offset, reply.Done)
		}
		event := Event{User: user.ID, Session: session, Action: req.Kind, Name: name, Offset: reply.Offset, Status: status}
		if reply.Error == "" {
			event.ShareID = reply.ShareID
			if req.Kind == "share_send" {
				event.Recipient = req.Recipient
			}
		}
		s.record(event)
	}
	return reply, received
}

func publicError(err error) string {
	var pathErr *os.PathError
	var linkErr *os.LinkError
	if errors.As(err, &pathErr) || errors.As(err, &linkErr) {
		return "文件操作失败或访问被拒绝"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "会话已取消"
	}
	message := err.Error()
	if len(message) > 220 || strings.ContainsAny(message, "/\\\r\n") {
		return "请求失败，请检查权限、文件状态及磁盘空间"
	}
	return message
}
