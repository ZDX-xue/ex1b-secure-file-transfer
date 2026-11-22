package service

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"time"

	"ex1b/internal/wire"
)

const (
	protocolSessionLimit  = 32
	protocolExchangeLimit = 160
	traceChunkInterval    = 256 * 1024
)

type ProtocolSession struct {
	ID                string    `json:"id"`
	User              string    `json:"user"`
	Role              string    `json:"role"`
	Peer              string    `json:"peer"`
	Version           string    `json:"version"`
	Cipher            string    `json:"cipher"`
	ClientFingerprint string    `json:"client_fingerprint,omitempty"`
	ServerFingerprint string    `json:"server_fingerprint,omitempty"`
	Started           time.Time `json:"started"`
	Ended             time.Time `json:"ended,omitzero"`
}

type ProtocolExchange struct {
	Time           time.Time `json:"time"`
	Session        string    `json:"session"`
	User           string    `json:"user"`
	ID             uint64    `json:"id"`
	Kind           string    `json:"kind"`
	RequestHeader  int       `json:"request_header"`
	ReplyHeader    int       `json:"reply_header"`
	RequestPayload int       `json:"request_payload"`
	ReplyPayload   int       `json:"reply_payload"`
	Offset         int64     `json:"offset"`
	AckOffset      int64     `json:"ack_offset"`
	HasOffset      bool      `json:"has_offset"`
	OK             bool      `json:"ok"`
	ElapsedMS      float64   `json:"elapsed_ms"`
}

type ProtocolSnapshot struct {
	Sessions  []ProtocolSession  `json:"sessions"`
	Exchanges []ProtocolExchange `json:"exchanges"`
	Limit     int                `json:"limit"`
}

// ProtocolSnapshot returns a bounded copy of the recent completed exchanges
// and successful TLS handshakes. It does not expose raw headers or payloads.
func (s *Server) ProtocolSnapshot() ProtocolSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ProtocolSnapshot{
		Sessions:  append([]ProtocolSession{}, s.protocolSessions...),
		Exchanges: append([]ProtocolExchange{}, s.protocolExchanges...),
		Limit:     protocolExchangeLimit,
	}
}

func staticServerFingerprint(cfg *tls.Config) string {
	// The service uses one fixed certificate. Leave the field empty if a
	// future configuration delegates certificate selection to a callback.
	if cfg.GetCertificate != nil || cfg.GetConfigForClient != nil ||
		len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) == 0 {
		return ""
	}
	hash := sha256.Sum256(cfg.Certificates[0].Certificate[0])
	return hex.EncodeToString(hash[:])
}

func appendBounded[T any](rows []T, record T, limit int) []T {
	if len(rows) == limit {
		copy(rows, rows[1:])
		rows = rows[:limit-1]
	}
	return append(rows, record)
}

// endProtocolSession and recordProtocolExchange are called with s.mu held.
func (s *Server) endProtocolSession(id string, now time.Time) {
	for i := len(s.protocolSessions) - 1; i >= 0; i-- {
		if s.protocolSessions[i].ID == id {
			s.protocolSessions[i].Ended = now
			return
		}
	}
}

func (s *Server) recordProtocolExchange(session *activeSession, request, response wire.Frame, replyHeader int, readAt time.Time) {
	now := time.Now()
	if !session.shouldTrace(request.Kind, request.Offset, now) {
		return
	}
	exchange := ProtocolExchange{
		Time: now, Session: session.ID, User: session.User, ID: request.ID, Kind: request.Kind,
		RequestHeader: request.HeaderBytes, ReplyHeader: replyHeader,
		RequestPayload: len(request.Body), ReplyPayload: len(response.Body),
		OK: response.Error == "", ElapsedMS: float64(now.Sub(readAt)) / float64(time.Millisecond),
	}
	switch request.Kind {
	case "put_begin", "put_chunk", "get_chunk":
		exchange.HasOffset = true
		exchange.Offset, exchange.AckOffset = request.Offset, response.Offset
	}
	s.protocolExchanges = appendBounded(s.protocolExchanges, exchange, protocolExchangeLimit)
}

func (session *activeSession) shouldTrace(kind string, offset int64, now time.Time) bool {
	last, seen := session.traceSeen[kind]
	switch kind {
	case "put_begin", "put_finish", "get_begin", "get_finish", "share_send":
		return true
	case "put_chunk", "get_chunk":
		if seen && (offset <= 0 || offset%traceChunkInterval != 0 || now.Sub(last) < 100*time.Millisecond) {
			return false
		}
	case "info", "list", "share_inbox", "share_outbox":
		if seen {
			return false
		}
	case "ping":
		if seen && now.Sub(last) < time.Minute {
			return false
		}
	default:
		return false
	}
	if session.traceSeen == nil {
		session.traceSeen = make(map[string]time.Time)
	}
	session.traceSeen[kind] = now
	return true
}
