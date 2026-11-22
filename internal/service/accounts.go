package service

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ex1b/internal/identity"
	"ex1b/internal/storage"
)

var accountID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// NewWeb enables enrollment after startup and binds the server to a persistent
// mailbox store. The caller must enroll existing owners before serving requests.
func NewWeb(cfg identity.ServerConfig, sharesPath string) (*Server, error) {
	shares, err := openShares(sharesPath)
	if err != nil {
		return nil, err
	}
	server, err := New(cfg)
	if err != nil {
		return nil, err
	}
	server.shares = shares
	server.tls.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("客户端证书验证失败")
		}
		server.mu.Lock()
		defer server.mu.Unlock()
		account := server.accounts[identity.Fingerprint(state.PeerCertificates[0])]
		if server.closed || account == nil || !account.enabled.Load() {
			return errors.New("客户端证书未登记或账号已停用")
		}
		return nil
	}
	return server, nil
}

// AddUser enrolls a verified certificate and reserves an exclusive data root.
// Repeating the same registration leaves the current enabled status intact.
func (s *Server) AddUser(user identity.User, maxFile int64, enabled bool) error {
	fingerprint, err := hex.DecodeString(user.Fingerprint)
	if err != nil || len(fingerprint) != sha256.Size || !accountID.MatchString(user.ID) ||
		!accountID.MatchString(user.Role) || user.BytesPerSecond <= 0 || user.QuotaBytes <= 0 || maxFile <= 0 || user.Root == "" {
		return errors.New("账号注册配置无效")
	}
	user.Fingerprint = hex.EncodeToString(fingerprint)
	root, err := filepath.Abs(user.Root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	user.Root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	info, err := os.Stat(user.Root)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("服务已关闭")
	}
	if existing := s.byID[user.ID]; existing != nil {
		if existing.User == user && existing.maxFile == maxFile {
			return nil
		}
		return errors.New("账号已登记其他凭据或目录")
	}
	if len(s.byID) >= 256 || s.accounts[user.Fingerprint] != nil {
		return errors.New("证书已被使用或账号数达到上限")
	}
	for _, account := range s.byID {
		if sameFile(account.Root, info) || withinRoot(account.Root, user.Root) || withinRoot(user.Root, account.Root) {
			return errors.New("账号目录必须独立")
		}
	}
	files, err := storage.Open(user.Root, maxFile, user.QuotaBytes)
	if err != nil {
		return err
	}
	account := &account{User: user, storage: files, rate: newLimiter(user.BytesPerSecond), maxFile: maxFile}
	account.enabled.Store(enabled)
	s.accounts[user.Fingerprint], s.byID[user.ID] = account, account
	return nil
}

func sameFile(path string, other os.FileInfo) bool {
	info, err := os.Stat(path)
	return err == nil && os.SameFile(info, other)
}

func withinRoot(root, child string) bool {
	rel, err := filepath.Rel(root, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// SetUserEnabled cancels active work and shuts down all sockets for disabled users.
func (s *Server) SetUserEnabled(id string, enabled bool) error {
	s.mu.Lock()
	account := s.byID[id]
	if s.closed || account == nil {
		s.mu.Unlock()
		return errors.New("账号未登记")
	}
	if previous := account.enabled.Swap(enabled); previous == enabled {
		s.mu.Unlock()
		return nil
	}
	status := "已启用账号"
	if !enabled {
		status = "已停用账号"
		for _, session := range s.sessions {
			if session.User == id {
				session.cancel()
				_ = session.conn.Close()
			}
		}
	}
	s.mu.Unlock()
	s.record(Event{User: "admin", Action: "account", Recipient: id, Status: status})
	return nil
}
