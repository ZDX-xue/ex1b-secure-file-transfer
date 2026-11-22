package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func demoDirectory(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "演示配置")
	if err := InitDemo(dir, "", ""); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDemoConfiguration(t *testing.T) {
	dir := demoDirectory(t)
	server, err := LoadServer(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	if server.Listen != DefaultListen || len(server.Users) != 2 || server.Users[0].BytesPerSecond != 256<<10 || server.Users[1].BytesPerSecond != 1<<20 {
		t.Fatalf("unexpected demo server config: %#v", server)
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials", "ca-key.pem")); !os.IsNotExist(err) {
		t.Fatal("CA signing key must stay in process memory")
	}
	if err := InitDemo(dir, "", ""); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected existing directory to be rejected: %v", err)
	}
	for index, id := range []string{"alice", "vip"} {
		client, err := LoadClient(filepath.Join(dir, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !filepath.IsAbs(client.Downloads) || client.UIListen != fmt.Sprintf("127.0.0.1:%d", 43952+index) || client.ServerName != "127.0.0.1" {
			t.Fatalf("unexpected client config: %#v", client)
		}
	}
}

func TestServerConfigurationRejectsConflictingIdentitiesAndRoots(t *testing.T) {
	dir := demoDirectory(t)
	path := filepath.Join(dir, "server.json")
	server, err := LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ServerConfig){
		"duplicate user":      func(c *ServerConfig) { c.Users[1].ID = c.Users[0].ID },
		"shared certificate":  func(c *ServerConfig) { c.Users[1].Fingerprint = c.Users[0].Fingerprint },
		"nested root":         func(c *ServerConfig) { c.Users[1].Root = "data/alice/nested" },
		"credentials exposed": func(c *ServerConfig) { c.Users[0].Root = "credentials" },
		"all interfaces":      func(c *ServerConfig) { c.Listen = "0.0.0.0:43951" },
		"unusable max file":   func(c *ServerConfig) { c.MaxFileBytes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			modified := server
			modified.Users = append([]User(nil), server.Users...)
			change(&modified)
			if err := saveConfig(dir, "server", modified); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadServer(path); err == nil {
				t.Fatal("server accepted the conflicting configuration")
			}
		})
	}
}

func TestExplicitLANIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lan")
	const address = "192.168.32.7:43951"
	const name = "transfer-lab.local"
	if err := InitDemo(dir, address, name); err != nil {
		t.Fatal(err)
	}
	serverConfig, err := LoadServer(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := LoadClient(filepath.Join(dir, "vip.json"))
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.Listen != address || clientConfig.Address != address || clientConfig.ServerName != name {
		t.Fatal("explicit LAN settings were not retained")
	}
	server, err := serverConfig.TLS()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(server.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{name, "192.168.32.7", "127.0.0.1", "::1", "localhost"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Fatal(err)
		}
	}
}

func exchange(server, client *tls.Config) (serverErr, clientErr error) {
	serverPipe, clientPipe := net.Pipe()
	deadline := time.Now().Add(4 * time.Second)
	_ = serverPipe.SetDeadline(deadline)
	_ = clientPipe.SetDeadline(deadline)
	serverResult := make(chan error, 1)
	go func() {
		defer serverPipe.Close()
		conn := tls.Server(serverPipe, server)
		err := conn.Handshake()
		if err == nil {
			_, err = conn.Write([]byte("ready"))
		}
		serverResult <- err
	}()
	conn := tls.Client(clientPipe, client)
	clientErr = conn.Handshake()
	if clientErr == nil {
		marker := make([]byte, len("ready"))
		_, clientErr = io.ReadFull(conn, marker)
		if clientErr == nil && string(marker) != "ready" {
			clientErr = fmt.Errorf("unexpected reply %q", marker)
		}
	}
	_ = clientPipe.Close()
	return <-serverResult, clientErr
}

func TestMutualTLS(t *testing.T) {
	dir := demoDirectory(t)
	configuredServer, err := LoadServer(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	configuredClient, err := LoadClient(filepath.Join(dir, "alice.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := configuredServer.TLS()
	if err != nil {
		t.Fatal(err)
	}
	client, err := configuredClient.TLS()
	if err != nil {
		t.Fatal(err)
	}
	if serverErr, clientErr := exchange(server, client); serverErr != nil || clientErr != nil {
		t.Fatalf("valid peer handshake failed, server=%v client=%v", serverErr, clientErr)
	}
	t.Run("server name must match", func(t *testing.T) {
		mismatch := client.Clone()
		mismatch.ServerName = "wrong.invalid"
		if _, err := exchange(server, mismatch); err == nil {
			t.Fatal("client accepted the wrong server identity")
		}
	})
	t.Run("server must verify client certificate", func(t *testing.T) {
		missing := client.Clone()
		missing.Certificates = nil
		if err, _ := exchange(server, missing); err == nil {
			t.Fatal("server accepted a client with no certificate")
		}
	})
	t.Run("valid client certificate still requires enrollment", func(t *testing.T) {
		configuredServer.Users = configuredServer.Users[1:]
		vipOnly, err := configuredServer.TLS()
		if err != nil {
			t.Fatal(err)
		}
		if err, _ := exchange(vipOnly, client); err == nil {
			t.Fatal("server accepted an unregistered client identity")
		}
	})
}
