// Package transfer implements sessions, multiplexed requests and file transfers.
package transfer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ex1b/internal/identity"
	"ex1b/internal/ui"
	"ex1b/internal/wire"
)

type Engine struct {
	ctx   context.Context
	addr  string
	tls   *tls.Config
	mu    sync.Mutex
	link  *session
	files sync.Map
}

func New(ctx context.Context, cfg identity.ClientConfig) (*Engine, error) {
	secure, err := cfg.TLS()
	if err != nil {
		return nil, err
	}
	return &Engine{ctx: ctx, addr: cfg.Address, tls: secure}, nil
}

type transportError struct{ error }

type session struct {
	conn    *tls.Conn
	done    chan struct{}
	once    sync.Once
	seq     atomic.Uint64
	pending sync.Map
	write   sync.Mutex
	slots   chan struct{}
}

func (e *Engine) ensure(ctx context.Context) (*session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx.Err() != nil {
		return nil, e.ctx.Err()
	}
	if e.link != nil {
		select {
		case <-e.link.done:
		default:
			return e.link, nil
		}
	}
	dial := tls.Dialer{
		Config: e.tls,
		NetDialer: &net.Dialer{Timeout: 4 * time.Second,
			KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 25 * time.Second, Interval: 10 * time.Second, Count: 3}},
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dial.DialContext(dialCtx, "tcp", e.addr)
	if err != nil {
		return nil, transportError{fmt.Errorf("连接文件服务: %w", err)}
	}
	s := &session{conn: conn.(*tls.Conn), done: make(chan struct{}), slots: make(chan struct{}, 6)}
	e.link = s
	go s.read()
	go s.keepAlive(e.ctx)
	return s, nil
}

// Drop closes the current session like an interrupted link. An in-progress
// transfer can reconnect and recover from its last confirmed offset.
func (e *Engine) Drop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.link != nil {
		e.link.close()
		e.link = nil
	}
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.done)
		// Close the underlying socket to wake both loops without waiting for TLS.
		_ = s.conn.NetConn().Close()
	})
}

func (s *session) read() {
	defer s.close()
	for {
		frame, err := wire.Read(s.conn)
		if err != nil {
			return
		}
		if pending, ok := s.pending.LoadAndDelete(frame.ID); ok {
			pending.(chan wire.Frame) <- frame
		}
	}
}

func (s *session) keepAlive(ctx context.Context) {
	tick := time.NewTicker(12 * time.Second)
	defer tick.Stop()
	defer s.close()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-tick.C:
			if _, err := s.call(ctx, wire.Frame{Header: wire.Header{Kind: "ping"}}); err != nil {
				return
			}
		}
	}
}

func (s *session) call(ctx context.Context, message wire.Frame) (wire.Frame, error) {
	deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	select {
	case <-s.done:
		return wire.Frame{}, transportError{errors.New("连接已中断")}
	case <-deadline.Done():
		return wire.Frame{}, deadline.Err()
	case s.slots <- struct{}{}:
	}
	defer func() { <-s.slots }()
	message.ID = s.seq.Add(1)
	response := make(chan wire.Frame, 1)
	s.pending.Store(message.ID, response)
	defer s.pending.Delete(message.ID)
	s.write.Lock()
	writeUntil, _ := deadline.Deadline()
	_ = s.conn.SetWriteDeadline(writeUntil)
	err := deadline.Err()
	if err == nil {
		err = wire.Write(s.conn, message)
	}
	s.write.Unlock()
	if err != nil {
		s.close()
		return wire.Frame{}, transportError{err}
	}
	select {
	case frame := <-response:
		if frame.Error != "" {
			return wire.Frame{}, errors.New(frame.Error)
		}
		if frame.Kind != message.Kind+"_reply" {
			s.close()
			return wire.Frame{}, errors.New("服务端响应类型不符")
		}
		return frame, nil
	case <-s.done:
		return wire.Frame{}, transportError{errors.New("连接已中断，等待恢复")}
	case <-deadline.Done():
		if ctx.Err() != nil {
			return wire.Frame{}, ctx.Err()
		}
		s.close()
		return wire.Frame{}, transportError{errors.New("等待服务端响应超时")}
	}
}

func (e *Engine) call(ctx context.Context, header wire.Header, body []byte) (wire.Frame, error) {
	conn, err := e.ensure(ctx)
	if err != nil {
		return wire.Frame{}, err
	}
	return conn.call(ctx, wire.Frame{Header: header, Body: body})
}

func (e *Engine) Info(ctx context.Context) (ui.Status, error) {
	r, err := e.call(ctx, wire.Header{Kind: "info"}, nil)
	return ui.Status{User: r.User, Role: r.Role, Session: r.Session, Rate: r.Rate, TLS: r.TLS}, err
}

func (e *Engine) List(ctx context.Context) ([]ui.File, error) {
	r, err := e.call(ctx, wire.Header{Kind: "list"}, nil)
	if err != nil {
		return nil, err
	}
	var result []ui.File
	if err := json.Unmarshal(r.Body, &result); err != nil {
		return nil, errors.New("服务端目录格式无效")
	}
	return result, nil
}

func retry(ctx context.Context, do func() error) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := do()
		var disconnected transportError
		if !errors.As(err, &disconnected) || attempt == 4 {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 450 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
