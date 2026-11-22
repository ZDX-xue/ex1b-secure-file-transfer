package transfer

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ex1b/internal/identity"
	"ex1b/internal/service"
	"ex1b/internal/ui"
	"ex1b/internal/wire"
)

type lab struct {
	ctx     context.Context
	server  *service.Server
	dir     string
	address string
}

func newLab(t *testing.T, maxConnections int) lab {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "demo")
	if err := identity.InitDemo(dir, "127.0.0.1:43951", ""); err != nil {
		t.Fatal(err)
	}
	cfg, err := identity.LoadServer(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	if maxConnections > 0 {
		cfg.MaxConnections = maxConnections
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := service.New(cfg)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	end := make(chan error, 1)
	go func() { end <- srv.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-end; err != nil {
			t.Error(err)
		}
		srv.Close()
	})
	return lab{ctx, srv, dir, listener.Addr().String()}
}

func (l lab) client(t *testing.T, name string) (*Engine, string) {
	t.Helper()
	cfg, err := identity.LoadClient(filepath.Join(l.dir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Address = l.address
	engine, err := New(l.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Drop)
	return engine, cfg.Downloads
}

func fixture(t *testing.T, directory, name string, n int) (string, []byte) {
	t.Helper()
	file := filepath.Join(directory, name)
	data := bytes.Repeat([]byte{0, 2, 24, 49, 90, 255, 'E', 'X'}, n/8)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	return file, data
}

func TestRealSessionsParallelTransferAndIdentityRate(t *testing.T) {
	lab := newLab(t, 0)
	alice, downloads := lab.client(t, "alice")
	vip, _ := lab.client(t, "vip")
	status, err := alice.Info(lab.ctx)
	if err != nil || status.User != "alice" || status.Session == "" {
		t.Fatalf("unexpected Alice authentication: %+v %v", status, err)
	}
	vs, err := vip.Info(lab.ctx)
	if err != nil || vs.User != "vip" || vs.Session == status.Session || vs.Rate <= status.Rate {
		t.Fatalf("unexpected VIP authentication: %+v %v", vs, err)
	}
	samples := t.TempDir()
	first, expected := fixture(t, samples, "a.bin", 320*1024)
	second, _ := fixture(t, samples, "b.bin", 320*1024)
	fast, _ := fixture(t, samples, "vip.bin", 640*1024)
	normalDone := make(chan error, 2)
	quickDone := make(chan struct {
		elapsed time.Duration
		err     error
	}, 1)
	start := time.Now()
	go func() { normalDone <- alice.Upload(lab.ctx, "a.bin", first, nil) }()
	go func() { normalDone <- alice.Upload(lab.ctx, "b.bin", second, nil) }()
	go func() {
		err := vip.Upload(lab.ctx, "vip.bin", fast, nil)
		quickDone <- struct {
			elapsed time.Duration
			err     error
		}{time.Since(start), err}
	}()
	for range 2 {
		if err := <-normalDone; err != nil {
			t.Fatal(err)
		}
	}
	normalElapsed := time.Since(start)
	quick := <-quickDone
	if quick.err != nil {
		t.Fatal(quick.err)
	}
	if normalElapsed < 2100*time.Millisecond || normalElapsed < quick.elapsed*2 {
		t.Fatalf("aggregate account caps not observed: alice %v vip %v", normalElapsed, quick.elapsed)
	}
	t.Logf("both accounts sent 640 KiB; normal concurrent %.2f KiB/s, VIP %.2f KiB/s", 640/normalElapsed.Seconds(), 640/quick.elapsed.Seconds())
	list, err := alice.List(lab.ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("Alice catalog: %+v %v", list, err)
	}
	if _, err := alice.Download(lab.ctx, "vip.bin", downloads, nil); err == nil {
		t.Fatal("Alice found a file in the VIP account")
	}
	next, _ := fixture(t, samples, "mix.bin", 192*1024)
	upDone := make(chan error, 1)
	go func() { upDone <- alice.Upload(lab.ctx, "mix.bin", next, nil) }()
	path, err := alice.Download(lab.ctx, "a.bin", downloads, nil)
	if upErr := <-upDone; upErr != nil {
		t.Fatal(upErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("download integrity: %v", err)
	}
	current, err := alice.Info(lab.ctx)
	if err != nil || current.Session != status.Session {
		t.Fatalf("requests changed the TCP session: %+v %v", current, err)
	}
}

func TestRealUploadAndDownloadResume(t *testing.T) {
	lab := newLab(t, 0)
	engine, downloads := lab.client(t, "alice")
	initial, err := engine.Info(lab.ctx)
	if err != nil {
		t.Fatal(err)
	}
	source, expected := fixture(t, t.TempDir(), "resume.bin", 160*1024)
	for _, method := range []string{"upload", "download"} {
		var dropped bool
		var resumed int64
		interrupt := func(p ui.Progress) {
			resumed = max(resumed, p.ResumedAt)
			if !dropped && p.Done >= wire.ChunkSize && p.Done < p.Total {
				dropped = true
				engine.Drop()
			}
		}
		if method == "upload" {
			err = engine.Upload(lab.ctx, "resume.bin", source, interrupt)
		} else {
			_, err = engine.Download(lab.ctx, "resume.bin", downloads, interrupt)
		}
		if err != nil || !dropped || resumed < wire.ChunkSize {
			t.Fatalf("%s did not resume after disconnect: %d %v", method, resumed, err)
		}
		t.Logf("%s resumed at %d bytes", method, resumed)
	}
	destination, err := os.ReadFile(filepath.Join(downloads, "resume.bin"))
	if err != nil || !bytes.Equal(destination, expected) {
		t.Fatalf("resumed download content: %v", err)
	}
	current, err := engine.Info(lab.ctx)
	if err != nil || current.Session == initial.Session {
		t.Fatalf("TCP link did not change across test: %+v %v", current, err)
	}
}

func TestAdmissionProtectsExistingSession(t *testing.T) {
	lab := newLab(t, 0)
	alice, _ := lab.client(t, "alice")
	vip, _ := lab.client(t, "vip")
	before, err := alice.Info(lab.ctx)
	if err != nil {
		t.Fatal(err)
	}
	lab.server.SetAccepting(false)
	if _, err := vip.Info(lab.ctx); err == nil {
		t.Fatal("a new connection was accepted while paused")
	}
	after, err := alice.Info(lab.ctx)
	if err != nil || after.Session != before.Session {
		t.Fatal(fmt.Errorf("existing session interrupted while paused: %w", err))
	}
	lab.server.SetAccepting(true)
	if _, err := vip.Info(lab.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityAndHeartbeat(t *testing.T) {
	lab := newLab(t, 1)
	alice, _ := lab.client(t, "alice")
	vip, _ := lab.client(t, "vip")
	first, err := alice.Info(lab.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vip.Info(lab.ctx); err == nil {
		t.Fatal("connection cap did not reject a second session")
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		state := lab.server.Snapshot()
		if len(state.Sessions) == 1 && state.Sessions[0].ID == first.Session && state.Sessions[0].Requests >= 2 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("did not receive a heartbeat on the original session")
		case <-poll.C:
		}
	}
	alice.Drop()
	if err := retry(lab.ctx, func() error {
		_, err := vip.Info(lab.ctx)
		return err
	}); err != nil {
		t.Fatalf("slot did not become usable after disconnect: %v", err)
	}
}
