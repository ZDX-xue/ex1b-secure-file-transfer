package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ex1b/internal/identity"
	"ex1b/internal/wire"
)

func TestProtocolTraceRecordsTLSAndFileExchanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	dir := filepath.Join(t.TempDir(), "demo")
	if err := identity.InitDemo(dir, "127.0.0.1:43951", ""); err != nil {
		t.Fatal(err)
	}
	config, err := identity.LoadServer(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWeb(config, filepath.Join(dir, "relay.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	connect := func(user string) (*relayClient, func()) {
		t.Helper()
		conf, err := identity.LoadClient(filepath.Join(dir, user+".json"))
		if err != nil {
			t.Fatal(err)
		}
		secure, err := conf.TLS()
		if err != nil {
			t.Fatal(err)
		}
		client, closeClient, err := relayConnect(ctx, server, secure)
		if err != nil {
			t.Fatal(err)
		}
		return client, closeClient
	}
	sender, closeSender := connect("alice")
	defer closeSender()
	receiver, closeReceiver := connect("vip")
	defer closeReceiver()

	senderTLS := sender.conn.ConnectionState()
	t.Logf("真实会话握手：%s / %s，双方证书已验证", tls.VersionName(senderTLS.Version), tls.CipherSuiteName(senderTLS.CipherSuite))
	senderInfo := sender.send(t, wire.Header{Kind: "info"}, nil)
	sender.send(t, wire.Header{Kind: "info"}, nil)
	receiverInfo := receiver.send(t, wire.Header{Kind: "info"}, nil)
	const filename = "private-fixture.dat"
	const message = "private-review-body"
	payload := bytes.Repeat([]byte("private-fixture-payload"), 4000)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	sender.upload(t, filename, payload, digest)
	share := sender.send(t, wire.Header{Kind: "share_send", Recipient: "vip", Name: filename, Message: message}, nil)
	receiver.send(t, wire.Header{Kind: "share_inbox"}, nil)
	begin := receiver.send(t, wire.Header{Kind: "get_begin", ShareID: share.ShareID}, nil)
	if begin.Size != int64(len(payload)) || begin.SHA256 != digest {
		t.Fatal("the relayed file has different metadata")
	}
	if got := receiver.receive(t, share.ShareID, digest, len(payload)); !bytes.Equal(got, payload) {
		t.Fatal("the relayed bytes differ")
	}
	receiver.send(t, wire.Header{Kind: "get_finish", ShareID: share.ShareID, Size: begin.Size, SHA256: digest}, nil)
	denied := receiver.request(t, wire.Frame{Header: wire.Header{Kind: "get_begin", Name: filename}})
	if denied.Error == "" {
		t.Fatal("the second account accessed a private path")
	}
	closeSender()
	closeReceiver()

	snapshot := server.ProtocolSnapshot()
	if len(snapshot.Sessions) != 2 || snapshot.Limit != protocolExchangeLimit {
		t.Fatalf("unexpected session snapshot %#v", snapshot.Sessions)
	}
	serverCert := identity.Fingerprint(senderTLS.PeerCertificates[0])
	var senderSeen, receiverSeen bool
	for _, session := range snapshot.Sessions {
		if session.Version != "TLS 1.3" || session.Cipher != tls.CipherSuiteName(senderTLS.CipherSuite) ||
			len(session.ClientFingerprint) != 64 || session.ServerFingerprint != serverCert ||
			session.Ended.IsZero() || session.Started.After(session.Ended) {
			t.Fatalf("incomplete TLS session %#v", session)
		}
		senderSeen = senderSeen || session.ID == senderInfo.Session && session.User == "alice"
		receiverSeen = receiverSeen || session.ID == receiverInfo.Session && session.User == "vip"
	}
	if !senderSeen || !receiverSeen {
		t.Fatal("trace did not identify both authenticated sessions")
	}
	var upload, download, rejected bool
	var senderInfoCount int
	for _, row := range snapshot.Exchanges {
		if row.RequestHeader <= 0 || row.ReplyHeader <= 0 || row.ElapsedMS < 0 {
			t.Fatalf("invalid metadata %#v", row)
		}
		if !upload && row.Kind == "put_chunk" && row.Session == senderInfo.Session && row.HasOffset &&
			row.Offset == 0 && row.AckOffset == wire.ChunkSize && row.RequestPayload == wire.ChunkSize {
			t.Logf("%s 请求 %d %s：请求报头 %d B，文件块 %d B；回执报头 %d B，确认偏移 %d B",
				row.Session, row.ID, row.Kind, row.RequestHeader, row.RequestPayload, row.ReplyHeader, row.AckOffset)
			upload = true
		}
		if !download && row.Kind == "get_chunk" && row.Session == receiverInfo.Session && row.HasOffset &&
			row.Offset == 0 && row.AckOffset == wire.ChunkSize && row.ReplyPayload == wire.ChunkSize {
			t.Logf("%s 请求 %d %s：请求报头 %d B，回执报头 %d B，回执文件块 %d B，下一偏移 %d B",
				row.Session, row.ID, row.Kind, row.RequestHeader, row.ReplyHeader, row.ReplyPayload, row.AckOffset)
			download = true
		}
		rejected = rejected || row.Kind == "get_begin" && row.ID == denied.ID && row.Session == receiverInfo.Session && !row.OK
		if row.Session == senderInfo.Session && row.Kind == "info" {
			senderInfoCount++
		}
	}
	if !upload || !download || !rejected || senderInfoCount != 1 {
		t.Fatalf("missing meaningful exchanges: upload %v, download %v, denied %v, info %d", upload, download, rejected, senderInfoCount)
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{filename, message, string(payload[:12]), digest, denied.Error} {
		if strings.Contains(string(snapshotJSON), private) {
			t.Fatal("protocol snapshot exposed private metadata")
		}
	}
}

func TestProtocolTraceExchangeLimit(t *testing.T) {
	server := &Server{}
	session := &activeSession{}
	started := time.Now()
	for i := 1; i <= 2*protocolExchangeLimit; i++ {
		server.recordProtocolExchange(session, wire.Frame{Header: wire.Header{
			ID: uint64(i), Kind: "put_begin",
		}}, wire.Frame{}, 50, started)
	}
	result := server.ProtocolSnapshot()
	if len(result.Exchanges) != protocolExchangeLimit ||
		result.Exchanges[0].ID != protocolExchangeLimit+1 ||
		result.Exchanges[protocolExchangeLimit-1].ID != 2*protocolExchangeLimit {
		t.Fatal("protocol snapshot did not cap and retain the most recent exchanges")
	}
}
