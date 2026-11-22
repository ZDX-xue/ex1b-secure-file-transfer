// Package webauth manages the Web portal's password-authenticated accounts.
package webauth

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
)

const (
	schemaVersion = 1
	iterations    = 600_000
	saltSize      = 16
	maxRegistry   = 1 << 20
	maxUsers      = 64
	maxDeleted    = 4096
)

var (
	ErrCredentials = errors.New("用户名、密码无效或账号已停用")
	ErrAccount     = errors.New("账号不存在")
	ErrExists      = errors.New("用户名已被使用")
	ErrPassword    = errors.New("密码应为 10 至 128 字节")
	ErrUsername    = errors.New("用户名须以小写字母开头，长度 3 至 32，可包含数字、下划线和短横线")
	ErrRole        = errors.New("只能注册普通用户或 VIP 用户")
	ErrAdmin       = errors.New("管理员账号受系统保护")
	ErrBusy        = errors.New("认证操作繁忙，请稍后重试")
	ErrCapacity    = errors.New("演示系统账号记录数已达上限")
)

var usernamePattern = regexp.MustCompile("^[a-z][a-z0-9_-]{2,31}$")

type User struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Enabled  bool   `json:"enabled"`
}

type credential struct {
	User
	Salt []byte `json:"salt"`
	Hash []byte `json:"hash"`
}

type registry struct {
	Version int          `json:"version"`
	Users   []credential `json:"users"`
	Deleted []string     `json:"deleted,omitempty"`
}

type Store struct {
	path    string
	mu      sync.RWMutex
	users   map[string]credential
	deleted map[string]struct{}
	kdf     chan struct{}
}

// Open loads the registry or creates its sole administrator at first startup.
// An existing registry always takes precedence over the bootstrap password.
func Open(path string, adminPassword string) (*Store, error) {
	if path == "" {
		return nil, errors.New("未配置账号注册表路径")
	}
	s := &Store{path: path, users: make(map[string]credential), deleted: make(map[string]struct{}), kdf: make(chan struct{}, 4)}
	users, deleted, err := readRegistry(path)
	if err == nil {
		s.users = users
		s.deleted = deleted
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	admin, err := s.password(User{Username: "admin", Role: "admin", Enabled: true}, adminPassword)
	if err != nil {
		return nil, fmt.Errorf("初始化管理员: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("创建账号目录: %w", err)
	}
	s.users["admin"] = admin
	if err := s.save(s.users, s.deleted); err != nil {
		return nil, err
	}
	return s, nil
}

func readRegistry(path string) (map[string]credential, map[string]struct{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, errors.New("账号注册表需要是普通文件")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRegistry+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxRegistry {
		return nil, nil, errors.New("账号注册表超过大小限制")
	}
	var settings registry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil || decoder.Decode(new(any)) != io.EOF ||
		settings.Version != schemaVersion || len(settings.Users) == 0 || len(settings.Users) > maxUsers || len(settings.Deleted) > maxDeleted {
		return nil, nil, errors.New("账号注册表格式无效")
	}
	users := make(map[string]credential, len(settings.Users))
	for _, account := range settings.Users {
		if !usernamePattern.MatchString(account.Username) || len(account.Salt) != saltSize || len(account.Hash) != sha256.Size {
			return nil, nil, errors.New("账号注册表记录无效")
		}
		if account.Username == "admin" {
			if account.Role != "admin" || !account.Enabled {
				return nil, nil, errors.New("账号注册表缺少有效管理员")
			}
		} else if account.Role != "normal" && account.Role != "vip" {
			return nil, nil, errors.New("账号注册表角色无效")
		}
		if _, exists := users[account.Username]; exists {
			return nil, nil, errors.New("账号注册表存在重复用户名")
		}
		users[account.Username] = account
	}
	if _, exists := users["admin"]; !exists {
		return nil, nil, errors.New("账号注册表缺少管理员")
	}
	deleted := make(map[string]struct{}, len(settings.Deleted))
	for _, name := range settings.Deleted {
		_, active := users[name]
		_, duplicate := deleted[name]
		if !usernamePattern.MatchString(name) || active || duplicate {
			return nil, nil, errors.New("账号注册表存在无效的已删除用户名")
		}
		deleted[name] = struct{}{}
	}
	return users, deleted, nil
}

func ordered(users map[string]credential) []credential {
	result := make([]credential, 0, len(users))
	for _, account := range users {
		result = append(result, account)
	}
	slices.SortFunc(result, func(a, b credential) int {
		switch {
		case a.Username < b.Username:
			return -1
		case a.Username > b.Username:
			return 1
		default:
			return 0
		}
	})
	return result
}

// save writes a complete replacement beside the current file and closes the
// staged file before renaming it. Callers only publish new state after success.
func (s *Store) save(users map[string]credential, deleted map[string]struct{}) error {
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".accounts-")
	if err != nil {
		return fmt.Errorf("创建账号注册表暂存文件: %w", err)
	}
	defer os.Remove(tmp.Name())
	encoder := json.NewEncoder(tmp)
	snapshot := registry{Version: schemaVersion, Users: ordered(users), Deleted: slices.Sorted(maps.Keys(deleted))}
	if err := encoder.Encode(snapshot); err != nil {
		tmp.Close()
		return fmt.Errorf("暂存账号注册表: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("同步账号注册表: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭账号注册表暂存文件: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("提交账号注册表: %w", err)
	}
	return nil
}

func (s *Store) derive(password string, salt []byte) ([]byte, error) {
	select {
	case s.kdf <- struct{}{}:
		defer func() { <-s.kdf }()
	default:
		return nil, ErrBusy
	}
	return pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
}

func (s *Store) password(user User, password string) (credential, error) {
	if len(password) < 10 || len(password) > 128 {
		return credential{}, ErrPassword
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return credential{}, err
	}
	digest, err := s.derive(password, salt)
	if err != nil {
		return credential{}, err
	}
	return credential{user, salt, digest}, nil
}

func (s *Store) Register(username, password, role string, provision func(User) error) (User, error) {
	if !usernamePattern.MatchString(username) || username == "admin" {
		return User{}, ErrUsername
	}
	if role != "normal" && role != "vip" {
		return User{}, ErrRole
	}
	user := User{Username: username, Role: role, Enabled: true}
	candidate, err := s.password(user, password)
	if err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return User{}, ErrExists
	}
	if _, reserved := s.deleted[username]; reserved {
		return User{}, ErrExists
	}
	if len(s.users) >= maxUsers {
		return User{}, ErrCapacity
	}
	if provision != nil {
		if err := provision(user); err != nil {
			return User{}, err
		}
	}
	if err := s.replace(candidate); err != nil {
		return User{}, err
	}
	return user, nil
}

// replace requires s.mu and leaves the currently visible login state untouched
// if writing the next snapshot fails.
func (s *Store) replace(candidate credential) error {
	next := maps.Clone(s.users)
	next[candidate.Username] = candidate
	if err := s.save(next, s.deleted); err != nil {
		return err
	}
	s.users = next
	return nil
}

func (s *Store) verify(username, password string) (credential, error) {
	if !usernamePattern.MatchString(username) || len(password) < 10 || len(password) > 128 {
		return credential{}, ErrCredentials
	}
	s.mu.RLock()
	account, exists := s.users[username]
	s.mu.RUnlock()
	if !exists {
		// Give a syntactically valid unknown username the same KDF work.
		account.Salt = make([]byte, saltSize)
		account.Hash = make([]byte, sha256.Size)
	}
	digest, err := s.derive(password, account.Salt)
	if err != nil {
		return credential{}, err
	}
	if subtle.ConstantTimeCompare(digest, account.Hash) != 1 || !exists || !account.Enabled {
		return credential{}, ErrCredentials
	}
	return account, nil
}

func (s *Store) Authenticate(username, password string) (User, error) {
	account, err := s.verify(username, password)
	if err != nil {
		return User{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	current := s.users[username]
	if !current.Enabled || subtle.ConstantTimeCompare(current.Hash, account.Hash) != 1 {
		return User{}, ErrCredentials
	}
	return current.User, nil
}

func (s *Store) Lookup(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	account, ok := s.users[username]
	return account.User, ok
}

func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	accounts := ordered(s.users)
	users := make([]User, 0, len(accounts))
	for _, account := range accounts {
		users = append(users, account.User)
	}
	return users
}

func (s *Store) SetEnabled(username string, enabled bool) (User, error) {
	if username == "admin" {
		return User{}, ErrAdmin
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	account, exists := s.users[username]
	if !exists {
		return User{}, ErrAccount
	}
	if account.Enabled != enabled {
		account.Enabled = enabled
		if err := s.replace(account); err != nil {
			return User{}, err
		}
	}
	return account.User, nil
}

func (s *Store) ChangePassword(username, current, newPassword string) error {
	account, err := s.verify(username, current)
	if err != nil {
		return err
	}
	next, err := s.password(account.User, newPassword)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	latest := s.users[username]
	if !latest.Enabled || subtle.ConstantTimeCompare(latest.Hash, account.Hash) != 1 {
		return ErrCredentials
	}
	return s.replace(next)
}

// ResetPassword replaces a member's credential without changing their role or
// access status. The administrator changes their own password in account settings.
func (s *Store) ResetPassword(username, newPassword string) error {
	if username == "admin" {
		return ErrAdmin
	}
	user, exists := s.Lookup(username)
	if !exists {
		return ErrAccount
	}
	next, err := s.password(user, newPassword)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.users[username]
	if !exists {
		return ErrAccount
	}
	next.User = current.User
	return s.replace(next)
}

// Delete removes the credential and reserves the username so a new account
// cannot inherit files or permissions associated with the deleted identity.
func (s *Store) Delete(username string) error {
	if username == "admin" {
		return ErrAdmin
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; !exists {
		return ErrAccount
	}
	if len(s.deleted) >= maxDeleted {
		return ErrCapacity
	}
	users := maps.Clone(s.users)
	delete(users, username)
	deleted := maps.Clone(s.deleted)
	deleted[username] = struct{}{}
	if err := s.save(users, deleted); err != nil {
		return err
	}
	s.users, s.deleted = users, deleted
	return nil
}
