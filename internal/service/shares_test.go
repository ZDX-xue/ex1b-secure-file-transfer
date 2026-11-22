package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"ex1b/internal/identity"
	"ex1b/internal/wire"
)

type relayClient struct {
	conn *tls.Conn
	id   uint64
}

func relayConnect(ctx context.Context, server *Server, cfg *tls.Config) (*relayClient, func(), error) {
	remote, local := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.handleSession(ctx, remote)
		close(done)
	}()
	finish := func() {
		_ = local.Close()
		<-done
	}
	deadline := time.Now().Add(8 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = local.SetDeadline(deadline)
	conn := tls.Client(local, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		finish()
		return nil, func() {}, err
	}
	return &relayClient{conn: conn}, finish, nil
}

func (c *relayClient) request(t *testing.T, request wire.Frame) wire.Frame {
	t.Helper()
	c.id++
	request.ID = c.id
	if err := wire.Write(c.conn, request); err != nil {
		t.Fatal(err)
	}
	response, err := wire.Read(c.conn)
	if err != nil || response.ID != c.id {
		t.Fatalf("response %d: %v", response.ID, err)
	}
	return response
}

func (c *relayClient) send(t *testing.T, header wire.Header, body []byte) wire.Frame {
	t.Helper()
	frame := c.request(t, wire.Frame{Header: header, Body: body})
	if frame.Error != "" {
		t.Fatal(frame.Error)
	}
	return frame
}

func (c *relayClient) upload(t *testing.T, name string, payload []byte, sha string) {
	t.Helper()
	header := wire.Header{Kind: "put_begin", Name: name, Size: int64(len(payload)), SHA256: sha}
	c.send(t, header, nil)
	header.Kind = "put_chunk"
	for i := 0; i < len(payload); i += wire.ChunkSize {
		header.Offset = int64(i)
		c.send(t, header, payload[i:min(i+wire.ChunkSize, len(payload))])
	}
	header.Kind, header.Offset = "put_finish", 0
	c.send(t, header, nil)
}

func (c *relayClient) receive(t *testing.T, id, sha string, size int) []byte {
	t.Helper()
	var received []byte
	for i := 0; i < size; i += wire.ChunkSize {
		chunk := c.send(t, wire.Header{Kind: "get_chunk", ShareID: id, SHA256: sha,
			Offset: int64(i), Limit: wire.ChunkSize}, nil)
		received = append(received, chunk.Body...)
	}
	return received
}

func TestLiveRelayACLIntegrityAndBilateralRate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	dir := filepath.Join(t.TempDir(), "demo")
	if err := identity.InitDemo(dir, "127.0.0.1:43951", ""); err != nil {
		t.Fatal(err)
	}
	config, err := identity.LoadServer(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	users := config.Users
	config.Users = nil
	mailPath := filepath.Join(dir, "relay.json")
	server, err := NewWeb(config, mailPath)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, user := range users {
		if err := server.AddUser(user, config.MaxFileBytes, true); err != nil {
			t.Fatal(err)
		}
		if err := server.AddUser(user, config.MaxFileBytes, true); err != nil {
			t.Fatalf("idempotent enrollment: %v", err)
		}
	}
	creds := func(id string) *tls.Config {
		t.Helper()
		conf, err := identity.LoadClient(filepath.Join(dir, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		tlsConfig, err := conf.TLS()
		if err != nil {
			t.Fatal(err)
		}
		return tlsConfig
	}
	aliceTLS := creds("alice")
	alice, closeAlice, err := relayConnect(ctx, server, aliceTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAlice()
	vip, closeVIP, err := relayConnect(ctx, server, creds("vip"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeVIP()
	aliceInfo := alice.send(t, wire.Header{Kind: "info"}, nil)
	vipInfo := vip.send(t, wire.Header{Kind: "info"}, nil)
	if aliceInfo.Rate >= vipInfo.Rate || aliceInfo.User != "alice" || vipInfo.User != "vip" {
		t.Fatal("the verified certificate did not determine the account and rate")
	}
	payload := bytes.Repeat([]byte("relay"), wire.ChunkSize)
	hash := sha256.Sum256(payload)
	sha := hex.EncodeToString(hash[:])
	const fileName = "balance.bin"
	alice.upload(t, fileName, payload, sha)
	message := vip.send(t, wire.Header{Kind: "share_send", Recipient: "alice", Message: "确认收到"}, nil)
	file := alice.send(t, wire.Header{Kind: "share_send", Recipient: "vip", Name: fileName, Message: "账单"}, nil)
	if file.ShareID == "" || message.ShareID == "" || file.ShareID == message.ShareID {
		t.Fatal("relay did not return distinct message and file identifiers")
	}
	var inbox []Share
	if err := json.Unmarshal(vip.send(t, wire.Header{Kind: "share_inbox"}, nil).Body, &inbox); err != nil ||
		len(inbox) != 1 || inbox[0].ID != file.ShareID || inbox[0].Sender != "alice" || inbox[0].SHA256 != sha {
		t.Fatalf("authorized VIP inbox: %+v %v", inbox, err)
	}
	if err := json.Unmarshal(alice.send(t, wire.Header{Kind: "share_inbox"}, nil).Body, &inbox); err != nil ||
		len(inbox) != 1 || inbox[0].ID != message.ShareID || inbox[0].Name != "" {
		t.Fatalf("authorized Alice inbox: %+v %v", inbox, err)
	}
	unauthorized := alice.request(t, wire.Frame{Header: wire.Header{Kind: "get_begin", ShareID: file.ShareID}})
	if unauthorized.Error == "" || unauthorized.Name != "" || unauthorized.SHA256 != "" {
		t.Fatal("a nonrecipient learned metadata through the shared-file route")
	}
	begin := vip.send(t, wire.Header{Kind: "get_begin", ShareID: file.ShareID}, nil)
	if begin.Name != fileName || begin.Size != int64(len(payload)) || begin.SHA256 != sha {
		t.Fatal("shared file version changed")
	}
	started := time.Now()
	received := vip.receive(t, file.ShareID, sha, len(payload))
	elapsed := time.Since(started)
	if !bytes.Equal(received, payload) || elapsed < 420*time.Millisecond {
		t.Fatalf("relay content or normal sender cap was lost: %v elapsed %v", len(received), elapsed)
	}
	t.Logf("VIP receiving from normal account took %s for %d bytes", elapsed, len(payload))
	vip.send(t, wire.Header{Kind: "get_finish", ShareID: file.ShareID, SHA256: sha, Size: int64(len(received))}, nil)
	vip.upload(t, "returned.bin", payload, sha)
	returned := vip.send(t, wire.Header{Kind: "share_send", Recipient: "alice", Name: "returned.bin"}, nil)
	started = time.Now()
	received = alice.receive(t, returned.ShareID, sha, len(payload))
	elapsed = time.Since(started)
	if !bytes.Equal(received, payload) || elapsed < 420*time.Millisecond {
		t.Fatalf("relay content or normal recipient cap was lost: %v elapsed %v", len(received), elapsed)
	}
	t.Logf("normal account receiving from VIP took %s for %d bytes", elapsed, len(payload))
	alice.send(t, wire.Header{Kind: "get_finish", ShareID: returned.ShareID, SHA256: sha, Size: int64(len(received))}, nil)
	traffic := server.Snapshot().Traffic
	if traffic.Received != 2*int64(len(payload)) || traffic.Sent != 2*int64(len(payload)) || traffic.Shared != 3 {
		t.Fatalf("incorrect relay statistics: %+v", traffic)
	}
	if err := server.SetUserEnabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.Read(alice.conn); err == nil {
		t.Fatal("disabled Alice session remained open")
	}
	blockedCtx, blockedCancel := context.WithTimeout(ctx, time.Second)
	defer blockedCancel()
	newAlice, closeNew, err := relayConnect(blockedCtx, server, aliceTLS)
	if err == nil {
		defer closeNew()
		// TLS 1.3 clients can finish their side before the server's final
		// certificate rejection arrives. The protected request must still fail.
		req := wire.Frame{Header: wire.Header{Kind: "info", ID: 1}}
		if err := wire.Write(newAlice.conn, req); err == nil {
			if frame, err := wire.Read(newAlice.conn); err == nil && frame.Error == "" {
				t.Fatal("disabled certificate established a new account session")
			}
		}
	}
	blocked := vip.request(t, wire.Frame{Header: wire.Header{Kind: "get_begin", ShareID: file.ShareID}})
	if blocked.Error == "" {
		t.Fatal("a disabled sender still exposed its file through relay")
	}
	if err := server.SetUserEnabled("alice", true); err != nil {
		t.Fatal(err)
	}
	if real := vip.send(t, wire.Header{Kind: "get_begin", ShareID: file.ShareID}, nil); real.SHA256 != sha {
		t.Fatal("shared file did not become accessible again after re-enable")
	}
	store, err := openShares(mailPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved, ok := store.find(file.ShareID); !ok || saved.SHA256 != sha {
		t.Fatal("share metadata did not survive reopening")
	}
	if _, err := alice.conn.Write([]byte{0}); err == nil {
		t.Fatal("old session was unexpectedly reusable")
	}
}
