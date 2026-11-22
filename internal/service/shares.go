package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"ex1b/internal/storage"
	"ex1b/internal/wire"
)

const (
	maxShares    = 512
	maxMailbox   = 256
	maxMessage   = 512
	maxShareFile = 4 << 20
)

// Share identifies one server-relayed message, optionally with an immutable
// snapshot reference to a published file. The file is stored only once.
type Share struct {
	ID        string    `json:"id"`
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Message   string    `json:"message"`
	Time      time.Time `json:"time"`
}

func (sh Share) valid() bool {
	id, err := hex.DecodeString(sh.ID)
	if err != nil || len(id) != 16 || !accountID.MatchString(sh.Sender) || !accountID.MatchString(sh.Recipient) ||
		sh.Sender == sh.Recipient || sh.Time.IsZero() || !validMessage(sh.Message) {
		return false
	}
	if sh.Name == "" {
		return sh.Message != "" && sh.SHA256 == "" && sh.Size == 0
	}
	digest, err := hex.DecodeString(sh.SHA256)
	return storage.ValidateName(sh.Name) == nil && sh.Size >= 0 && err == nil && len(digest) == sha256.Size
}

func validMessage(text string) bool {
	if len(text) > maxMessage || !utf8.ValidString(text) {
		return false
	}
	for _, letter := range text {
		if unicode.IsControl(letter) && letter != '\n' && letter != '\t' {
			return false
		}
	}
	return true
}

type shareStore struct {
	mu      sync.RWMutex
	path    string
	records []Share // oldest first
}

func openShares(path string) (*shareStore, error) {
	if path == "" {
		return nil, errors.New("消息存储路径不能为空")
	}
	store := &shareStore{path: path}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxShareFile+1))
	if err != nil || len(data) > maxShareFile {
		return nil, errors.New("消息存档超过限制或无法读取")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&store.records); err != nil || dec.Decode(new(any)) != io.EOF || len(store.records) > maxShares {
		return nil, errors.New("消息存档格式无效")
	}
	seen := make(map[string]bool, len(store.records))
	for _, entry := range store.records {
		if !entry.valid() || seen[entry.ID] {
			return nil, errors.New("消息存档包含无效记录")
		}
		seen[entry.ID] = true
	}
	return store, nil
}

func (ss *shareStore) count() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.records)
}

func (ss *shareStore) find(id string) (Share, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for _, sh := range ss.records {
		if sh.ID == id {
			return sh, true
		}
	}
	return Share{}, false
}

func (ss *shareStore) list(id string, outgoing bool) ([]byte, error) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	// Ensure the single inbox reply always fits the transfer frame even when
	// UTF-8 fields expand during JSON escaping. Preserve newest-first order.
	var buffer bytes.Buffer
	buffer.WriteByte('[')
	for i, matched := len(ss.records)-1, 0; i >= 0 && matched < maxMailbox; i-- {
		sh := ss.records[i]
		owner := sh.Recipient
		if outgoing {
			owner = sh.Sender
		}
		if owner != id {
			continue
		}
		entry, err := json.Marshal(sh)
		if err != nil {
			return nil, err
		}
		if buffer.Len()+len(entry)+2 > wire.MaxBody {
			break
		}
		if matched != 0 {
			buffer.WriteByte(',')
		}
		buffer.Write(entry)
		matched++
	}
	buffer.WriteByte(']')
	return buffer.Bytes(), nil
}

func (ss *shareStore) append(entry Share) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if len(ss.records) >= maxShares {
		return errors.New("服务器中转消息达到保存上限")
	}
	for _, old := range ss.records {
		if old.ID == entry.ID {
			return errors.New("消息标识冲突，请重试")
		}
	}
	records := append(append(make([]Share, 0, len(ss.records)+1), ss.records...), entry)
	if err := ss.save(records); err != nil {
		return errors.New("无法保存中转消息")
	}
	ss.records = records
	return nil
}

func (ss *shareStore) save(records []Share) error {
	dir := filepath.Dir(ss.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".mailbox-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(records)
	if err == nil {
		err = file.Sync()
	}
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), ss.path)
}

func (s *Server) mailbox(id string, outgoing bool) ([]byte, error) {
	if s.shares == nil {
		return nil, errors.New("服务端中转功能未启用")
	}
	return s.shares.list(id, outgoing)
}

func (s *Server) send(sender *account, recipient, name, message string) (string, error) {
	if s.shares == nil {
		return "", errors.New("服务端中转功能未启用")
	}
	message = strings.TrimSpace(message)
	if !validMessage(message) || (name == "" && message == "") {
		return "", errors.New("消息应包含文件或 512 字节以内的文字")
	}
	if !accountID.MatchString(recipient) || recipient == sender.ID {
		return "", errors.New("请选择其他已启用账号")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", errors.New("无法生成消息标识")
	}
	entry := Share{ID: hex.EncodeToString(id[:]), Sender: sender.ID, Recipient: recipient,
		Name: name, Message: message, Time: time.Now().UTC()}
	if name != "" {
		file, err := sender.storage.Info(name)
		if err != nil {
			return "", err
		}
		entry.Name, entry.Size, entry.SHA256 = file.Name, file.Size, file.SHA256
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.byID[recipient]
	if s.closed || target == nil || !target.enabled.Load() || !sender.enabled.Load() {
		return "", errors.New("发送或接收账号未启用")
	}
	if err := s.shares.append(entry); err != nil {
		return "", err
	}
	return entry.ID, nil
}

func (s *Server) download(ctx context.Context, user *account, req wire.Frame, reply *wire.Frame) error {
	source, name := user, req.Name
	var share Share
	if req.ShareID != "" {
		if s.shares == nil || len(req.ShareID) != 32 {
			return errors.New("找不到可下载的共享文件")
		}
		item, ok := s.shares.find(req.ShareID)
		if !ok || item.Recipient != user.ID || item.Name == "" {
			return errors.New("找不到可下载的共享文件")
		}
		s.mu.Lock()
		source = s.byID[item.Sender]
		s.mu.Unlock()
		if source == nil || !source.enabled.Load() {
			return errors.New("共享来源当前不可用")
		}
		share, name = item, item.Name
	}
	file, err := source.storage.Info(name)
	if err != nil {
		return err
	}
	if share.ID != "" && (file.SHA256 != share.SHA256 || file.Size != share.Size) {
		return errors.New("共享文件版本已经改变")
	}
	reply.Name, reply.ShareID = file.Name, share.ID
	switch req.Kind {
	case "get_begin":
		reply.Size, reply.SHA256 = file.Size, file.SHA256
	case "get_chunk":
		if req.Limit <= 0 || req.Limit > wire.ChunkSize {
			return errors.New("下载分块大小无效")
		}
		body, err := source.storage.Read(file.Name, req.SHA256, req.Offset, req.Limit)
		if err != nil {
			return err
		}
		if err := user.rate.Wait(ctx, len(body)); err != nil {
			return err
		}
		// Each account has one shared token bucket. Relay data is charged to
		// both owners, so the slower plan constrains either transfer direction.
		if source != user {
			if err := source.rate.Wait(ctx, len(body)); err != nil {
				return err
			}
			if !source.enabled.Load() {
				return errors.New("共享来源当前不可用")
			}
		}
		reply.Body = body
		reply.Offset = req.Offset + int64(len(body))
	case "get_finish":
		if file.Size != req.Size || file.SHA256 != req.SHA256 {
			return errors.New("下载校验回执与文件版本不一致")
		}
		reply.Done = true
	}
	return nil
}
