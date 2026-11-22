package storage

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func digest(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}

func openStore(t *testing.T, dir string, maxFile, quota int64) *Store {
	t.Helper()
	store, err := Open(dir, maxFile, quota)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestRestartResumeAndRead(t *testing.T) {
	dir := t.TempDir()
	store := openStore(t, dir, 32, 64)
	name, content := "课程资料.txt", "0123456789"
	size, sha := int64(len(content)), digest(content)
	if offset, done, err := store.Begin(name, size, sha); err != nil || done || offset != 0 {
		t.Fatal(offset, done, err)
	}
	for range 2 {
		if offset, err := store.Write(name, size, sha, 0, []byte(content[:4])); err != nil || offset != 4 {
			t.Fatal(offset, err)
		}
	}
	if err := store.Finish(name, size, sha); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
	if _, err := store.Info(name); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if files, err := store.List(); err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, dir, 32, 64)
	if offset, done, err := store.Begin(name, size, sha); err != nil || done || offset != 4 {
		t.Fatal(offset, done, err)
	}
	if offset, err := store.Write(name, size, sha, 5, []byte(content[5:])); !errors.Is(err, ErrOffset) || offset != 4 {
		t.Fatal(offset, err)
	}
	if offset, err := store.Write(name, size, sha, 4, []byte(content[4:])); err != nil || offset != size {
		t.Fatal(offset, err)
	}
	for range 2 {
		if err := store.Finish(name, size, sha); err != nil {
			t.Fatal(err)
		}
	}
	if offset, done, err := store.Begin(name, size, sha); err != nil || !done || offset != size {
		t.Fatal(offset, done, err)
	}
	if files, err := store.List(); err != nil || len(files) != 1 || files[0] != (File{name, size, sha}) {
		t.Fatal(files, err)
	}
	if data, err := store.Read(name, sha, 4, 8); err != nil || string(data) != content[4:] {
		t.Fatal(string(data), err)
	}
	if _, err := store.Read(name, digest("different version"), 0, 8); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

func TestHashMismatchResetsStaging(t *testing.T) {
	store := openStore(t, t.TempDir(), 32, 8)
	const name, content = "upload.dat", "correct"
	size, sha := int64(len(content)), digest(content)
	if _, _, err := store.Begin(name, size, sha); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin("another.dat", 2, digest("ok")); !errors.Is(err, ErrQuota) {
		t.Fatal(err)
	}
	if _, err := store.Write(name, size, sha, 0, []byte("invalid")); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(name, size, sha); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
	if offset, done, err := store.Begin(name, size, sha); err != nil || done || offset != 0 {
		t.Fatal(offset, done, err)
	}
	if _, err := store.Write(name, size, sha, 0, []byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(name, size, sha); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(name, size, digest("another")); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

func TestAccountIsolationAndPortableNames(t *testing.T) {
	base := t.TempDir()
	alice := openStore(t, filepath.Join(base, "alice"), 64, 128)
	bob := openStore(t, filepath.Join(base, "bob"), 64, 128)
	const name = "共享演示（新版）.txt"
	sha := digest("")
	if _, _, err := alice.Begin(name, 0, sha); err != nil {
		t.Fatal(err)
	}
	if err := alice.Finish(name, 0, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Info(name); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if files, err := bob.List(); err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
	for _, invalid := range []string{"", "not/path", `dir\file`, "disk:stream", "NUL.txt", "COM¹.txt", "a.", "a ", "a\x00b", strings.Repeat("a", 181)} {
		if err := ValidateName(invalid); !errors.Is(err, ErrInvalid) {
			t.Errorf("accepted %q; error: %v", invalid, err)
		}
	}
}
