package webauth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	initialAdmin = "test admin password"
	firstPass    = "long user password"
	nextPass     = "changed user password"
)

func TestAccountLifecycleAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := Open(path, initialAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if admin, err := store.Authenticate("admin", initialAdmin); err != nil || admin.Role != "admin" {
		t.Fatalf("bootstrap administrator: %+v %v", admin, err)
	}
	var provisioned User
	vip, err := store.Register("alice", firstPass, "vip", func(user User) error {
		provisioned = user
		return nil
	})
	if err != nil || vip.Username != "alice" || vip.Role != "vip" || !vip.Enabled || vip != provisioned {
		t.Fatalf("registered identity: %+v, provisioned: %+v, error: %v", vip, provisioned, err)
	}
	if _, err := store.Register("alice", firstPass, "vip", func(User) error {
		t.Error("duplicate registration should not provision again")
		return nil
	}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate registration: %v", err)
	}
	if err := store.ChangePassword("alice", firstPass, nextPass); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate("alice", firstPass); !errors.Is(err, ErrCredentials) {
		t.Fatalf("old password remained valid: %v", err)
	}
	if _, err := store.SetEnabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate("alice", nextPass); !errors.Is(err, ErrCredentials) {
		t.Fatalf("disabled account authenticated: %v", err)
	}

	reopened, err := Open(path, "unused bootstrap value")
	if err != nil {
		t.Fatal(err)
	}
	if users := reopened.List(); len(users) != 2 || users[1].Enabled || users[1].Role != "vip" {
		t.Fatalf("incorrect persisted account state: %+v", users)
	}
	if _, err := reopened.Authenticate("admin", initialAdmin); err != nil {
		t.Fatalf("bootstrap option reset existing password: %v", err)
	}
	if _, err := reopened.SetEnabled("alice", true); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Authenticate("alice", nextPass); err != nil {
		t.Fatalf("re-enabled account: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{initialAdmin, firstPass, nextPass} {
		if bytes.Contains(data, []byte(password)) {
			t.Fatal("account storage contains a plaintext password")
		}
	}
}

func TestRegistrationRulesAndFailedProvision(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.json"), initialAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user, password, role string
		want                 error
	}{
		{"../abc", firstPass, "normal", ErrUsername},
		{"admin", firstPass, "vip", ErrUsername},
		{"bob", firstPass, "admin", ErrRole},
		{"bob", "short", "normal", ErrPassword},
	} {
		if _, err := store.Register(tc.user, tc.password, tc.role, nil); !errors.Is(err, tc.want) {
			t.Errorf("invalid registration accepted for %q: %v", tc.user, err)
		}
	}
	if _, err := store.SetEnabled("admin", false); !errors.Is(err, ErrAdmin) {
		t.Fatalf("admin disable: %v", err)
	}
	badProvision := errors.New("fixture provision stopped")
	if _, err := store.Register("bob", firstPass, "normal", func(User) error { return badProvision }); !errors.Is(err, badProvision) {
		t.Fatalf("registration failure: %v", err)
	}
	if _, ok := store.Lookup("bob"); ok {
		t.Fatal("failed provision left an active account")
	}
}

func TestPersistenceFailureDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "accounts.json"), initialAdmin)
	if err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(dir, "missing", "accounts.json")
	if _, err := store.Register("alice", firstPass, "normal", nil); err == nil {
		t.Fatal("registration should fail if commit cannot be written")
	}
	if _, ok := store.Lookup("alice"); ok {
		t.Fatal("failed disk write changed visible registry")
	}
}
