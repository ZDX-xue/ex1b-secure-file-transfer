// Package storage manages each account's bounded, resumable file storage.
package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxChunkBytes bounds both a file data request and the corresponding result.
	MaxChunkBytes = 1024 * 1024
	maxObjects    = 64
	maxNameBytes  = 180
	maxMetaBytes  = 4096
	pendingDir    = "pending"
	publishedDir  = "published"
	newDir        = "pending/.new"
)

var (
	ErrInvalid   = errors.New("文件名、元数据或数据块无效")
	ErrNotFound  = errors.New("文件或传输任务不存在")
	ErrConflict  = errors.New("文件名已被其他内容占用")
	ErrOffset    = errors.New("数据块偏移与保存进度不符")
	ErrQuota     = errors.New("超出文件大小、文件数量或账户存储配额")
	ErrIntegrity = errors.New("文件长度或 SHA-256 校验失败")
	ErrStorage   = errors.New("服务端文件读写失败")
)

// File identifies a file version within one account's storage.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type entry struct {
	file File
	done bool
}

// Store owns one account root. One server instance should manage a given root.
type Store struct {
	mu       sync.Mutex
	root     *os.Root
	maxFile  int64
	quota    int64
	reserved int64
	entries  map[string]entry
	closed   bool
}

// Open prepares and validates the account's storage, recovering staged transfers.
// A pending transfer reserves its complete advertised size against the account quota.
func Open(dir string, maxFileBytes, quotaBytes int64) (*Store, error) {
	if dir == "" || maxFileBytes <= 0 || quotaBytes <= 0 {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, ErrStorage
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ErrStorage
	}
	store := &Store{
		root: root, maxFile: maxFileBytes, quota: quotaBytes,
		entries: make(map[string]entry),
	}
	if err := store.load(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) load() error {
	for _, dir := range []string{pendingDir, publishedDir} {
		if err := s.root.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return ErrStorage
		}
		info, err := s.root.Lstat(dir)
		if err != nil || !info.IsDir() {
			return ErrStorage
		}
	}
	// A crash during Begin may leave an object whose metadata was never published.
	if err := s.root.RemoveAll(newDir); err != nil {
		return ErrStorage
	}
	if err := s.loadCollection(publishedDir, true); err != nil {
		return err
	}
	return s.loadCollection(pendingDir, false)
}

func (s *Store) loadCollection(collection string, done bool) error {
	directory, err := s.root.Open(collection)
	if err != nil {
		return ErrStorage
	}
	children, err := directory.ReadDir(maxObjects + 1)
	closeErr := directory.Close()
	if (err != nil && !errors.Is(err, io.EOF)) || closeErr != nil {
		return ErrStorage
	}
	if len(children)+len(s.entries) > maxObjects {
		return ErrQuota
	}
	for _, child := range children {
		key := child.Name()
		if !child.IsDir() || !validDigest(key) {
			return ErrStorage
		}
		object := path.Join(collection, key)
		file, err := s.readMetadata(path.Join(object, "meta.json"))
		if err != nil || validateFile(file) != nil || key != nameKey(file.Name) {
			return ErrStorage
		}
		if file.Size > s.maxFile || file.Size > s.quota-s.reserved {
			return ErrQuota
		}
		info, err := s.root.Lstat(path.Join(object, "payload"))
		if err != nil || !info.Mode().IsRegular() || info.Size() > file.Size || (done && info.Size() != file.Size) {
			return ErrStorage
		}
		if _, exists := s.entries[key]; exists {
			return ErrStorage
		}
		s.entries[key] = entry{file: file, done: done}
		s.reserved += file.Size
	}
	return nil
}

func (s *Store) readMetadata(name string) (File, error) {
	var metadata File
	info, err := s.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxMetaBytes {
		return metadata, ErrStorage
	}
	file, err := s.root.Open(name)
	if err != nil {
		return metadata, ErrStorage
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMetaBytes+1))
	if err != nil || len(data) > maxMetaBytes || json.Unmarshal(data, &metadata) != nil {
		return metadata, ErrStorage
	}
	return metadata, nil
}

// Close releases the account root handle after its active operations finish.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.root.Close()
}

// ValidateName accepts a single, portable UTF-8 filename component.
func ValidateName(name string) error {
	if !utf8.ValidString(name) || name == "" || len(name) > maxNameBytes ||
		name == "." || name == ".." || strings.TrimSpace(name) != name ||
		strings.HasSuffix(name, ".") || strings.ContainsAny(name, `<>:"/\|?*`) {
		return ErrInvalid
	}
	for _, character := range name {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return ErrInvalid
		}
	}
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return ErrInvalid
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		switch base[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return ErrInvalid
		}
	}
	return nil
}

func nameKey(name string) string {
	digest := sha256.Sum256([]byte(name))
	return hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, digit := range value {
		if !(digit >= '0' && digit <= '9') && !(digit >= 'a' && digit <= 'f') {
			return false
		}
	}
	return true
}

func validateFile(file File) error {
	if ValidateName(file.Name) != nil || file.Size < 0 || !validDigest(file.SHA256) {
		return ErrInvalid
	}
	return nil
}

func payloadPath(collection, key string) string {
	return path.Join(collection, key, "payload")
}

func (s *Store) beginObject(key string, metadata File) error {
	if err := s.root.Mkdir(newDir, 0o700); err != nil {
		return ErrStorage
	}
	defer s.root.RemoveAll(newDir)
	file, err := s.root.OpenFile(path.Join(newDir, "payload"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrStorage
	}
	if err := file.Close(); err != nil {
		return ErrStorage
	}
	body, err := json.Marshal(metadata)
	if err != nil {
		return ErrStorage
	}
	meta, err := s.root.OpenFile(path.Join(newDir, "meta.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrStorage
	}
	_, writeErr := meta.Write(body)
	syncErr := meta.Sync()
	closeErr := meta.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return ErrStorage
	}
	if err := s.root.Rename(newDir, path.Join(pendingDir, key)); err != nil {
		return ErrStorage
	}
	return nil
}

// Begin reserves an upload or returns the saved offset of the same file version.
func (s *Store) Begin(name string, size int64, sha string) (int64, bool, error) {
	file := File{Name: name, Size: size, SHA256: sha}
	if err := validateFile(file); err != nil {
		return 0, false, err
	}
	key := nameKey(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, false, ErrStorage
	}
	if saved, ok := s.entries[key]; ok {
		if saved.file != file {
			return 0, false, ErrConflict
		}
		if saved.done {
			return size, true, nil
		}
		info, err := s.root.Lstat(payloadPath(pendingDir, key))
		if err != nil || !info.Mode().IsRegular() || info.Size() > size {
			return 0, false, ErrStorage
		}
		return info.Size(), false, nil
	}
	if size > s.maxFile || size > s.quota-s.reserved || len(s.entries) >= maxObjects {
		return 0, false, ErrQuota
	}
	if err := s.beginObject(key, file); err != nil {
		return 0, false, err
	}
	s.entries[key] = entry{file: file}
	s.reserved += size
	return 0, false, nil
}

func (s *Store) matchingUpload(key string, expected File) (entry, error) {
	if s.closed {
		return entry{}, ErrStorage
	}
	saved, ok := s.entries[key]
	if !ok {
		return entry{}, ErrNotFound
	}
	if saved.file != expected {
		return entry{}, ErrConflict
	}
	return saved, nil
}

// Write appends a chunk at the current offset and syncs it before acknowledging.
// A byte-identical replay of an already saved chunk is safe to acknowledge again.
func (s *Store) Write(name string, size int64, sha string, offset int64, data []byte) (int64, error) {
	expected := File{Name: name, Size: size, SHA256: sha}
	if validateFile(expected) != nil || offset < 0 || offset > size ||
		len(data) == 0 || len(data) > MaxChunkBytes || int64(len(data)) > size-offset {
		return 0, ErrInvalid
	}
	key := nameKey(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.matchingUpload(key, expected)
	if err != nil {
		return 0, err
	}
	if saved.done {
		return size, ErrConflict
	}
	file, err := s.root.OpenFile(payloadPath(pendingDir, key), os.O_RDWR, 0)
	if err != nil {
		return 0, ErrStorage
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > size {
		return 0, ErrStorage
	}
	position := info.Size()
	if offset < position && int64(len(data)) <= position-offset {
		prior := make([]byte, len(data))
		if _, err := file.ReadAt(prior, offset); err != nil {
			return position, ErrStorage
		}
		if bytes.Equal(data, prior) {
			return position, nil
		}
	}
	if offset != position {
		return position, ErrOffset
	}
	if _, err := file.WriteAt(data, offset); err != nil {
		_ = file.Truncate(position)
		_ = file.Sync()
		return position, ErrStorage
	}
	if err := file.Sync(); err != nil {
		_ = file.Truncate(position)
		_ = file.Sync()
		return position, ErrStorage
	}
	return offset + int64(len(data)), nil
}

// Finish verifies and publishes an upload. Repeated completion is idempotent.
func (s *Store) Finish(name string, size int64, sha string) error {
	expected := File{Name: name, Size: size, SHA256: sha}
	if err := validateFile(expected); err != nil {
		return err
	}
	key := nameKey(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.matchingUpload(key, expected)
	if err != nil || saved.done {
		return err
	}
	if err := s.verifyUpload(key, expected); err != nil {
		return err
	}
	if err := s.root.Rename(path.Join(pendingDir, key), path.Join(publishedDir, key)); err != nil {
		return ErrStorage
	}
	s.entries[key] = entry{file: expected, done: true}
	return nil
}

func (s *Store) verifyUpload(key string, expected File) error {
	file, err := s.root.OpenFile(payloadPath(pendingDir, key), os.O_RDWR, 0)
	if err != nil {
		return ErrStorage
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrStorage
	}
	if info.Size() != expected.Size {
		return ErrIntegrity
	}
	digest := sha256.New()
	size, err := io.CopyN(digest, file, expected.Size)
	if err != nil || size != expected.Size {
		return ErrStorage
	}
	if hex.EncodeToString(digest.Sum(nil)) != expected.SHA256 {
		// A full but invalid file can be restarted without freeing another slot.
		if err := file.Truncate(0); err != nil {
			return ErrStorage
		}
		if err := file.Sync(); err != nil {
			return ErrStorage
		}
		return ErrIntegrity
	}
	if err := file.Sync(); err != nil {
		return ErrStorage
	}
	return nil
}

func (s *Store) published(key string) (File, error) {
	if s.closed {
		return File{}, ErrStorage
	}
	saved, ok := s.entries[key]
	if !ok || !saved.done {
		return File{}, ErrNotFound
	}
	return saved.file, nil
}

// Info returns metadata only for a fully verified version.
func (s *Store) Info(name string) (File, error) {
	if err := ValidateName(name); err != nil {
		return File{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.published(nameKey(name))
}

// Read returns a bounded chunk of a verified file, using its digest as the version.
func (s *Store) Read(name, sha string, offset int64, limit int) ([]byte, error) {
	if ValidateName(name) != nil || !validDigest(sha) || offset < 0 || limit <= 0 || limit > MaxChunkBytes {
		return nil, ErrInvalid
	}
	key := nameKey(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, err := s.published(key)
	if err != nil {
		return nil, err
	}
	if metadata.SHA256 != sha {
		return nil, ErrConflict
	}
	if offset > metadata.Size {
		return nil, ErrOffset
	}
	if offset == metadata.Size {
		return []byte{}, nil
	}
	file, err := s.root.Open(payloadPath(publishedDir, key))
	if err != nil {
		return nil, ErrStorage
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != metadata.Size {
		return nil, ErrStorage
	}
	data := make([]byte, min(int64(limit), metadata.Size-offset))
	if _, err := file.ReadAt(data, offset); err != nil {
		return nil, ErrStorage
	}
	return data, nil
}

// List returns a name-sorted snapshot of completed files, with at most 64 entries.
func (s *Store) List() ([]File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStorage
	}
	files := make([]File, 0, len(s.entries))
	for _, saved := range s.entries {
		if saved.done {
			files = append(files, saved.file)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}
