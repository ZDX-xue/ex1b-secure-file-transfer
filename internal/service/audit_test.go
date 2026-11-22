package service

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTransferAuditStages(t *testing.T) {
	for _, tc := range []struct {
		action, name string
		offset       int64
		alreadyDone  bool
		want         string
	}{
		{action: "put_begin", want: "已受理，等待上传文件"},
		{action: "put_begin", offset: 64, want: "已确认续传位置"},
		{action: "put_begin", offset: 64, alreadyDone: true, want: "文件已在服务端入库"},
		{action: "put_finish", want: "SHA-256 校验通过，已存入服务端"},
		{action: "share_send", name: "file.txt", want: "已投递收件箱，待收件人下载"},
		{action: "share_send", want: "文字消息已投递收件箱"},
		{action: "get_begin", want: "已返回文件信息，准备下载"},
		{action: "get_finish", want: "接收端已确认文件完整性"},
	} {
		if got := transferAuditStatus(tc.action, tc.name, tc.offset, tc.alreadyDone); got != tc.want {
			t.Errorf("%+v: got %q", tc, got)
		}
	}
}

func TestLoadAuditTailKeepsRecentEventsAndNormalizesLegacyStatuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if events, err := loadAuditTail(path); err != nil || len(events) != 0 {
		t.Fatalf("missing file: got %+v, %v", events, err)
	}
	var data bytes.Buffer
	now := time.Now().UTC()
	encoder := json.NewEncoder(&data)
	for i := range maxAuditEvents + 10 {
		event := Event{Time: now.Add(time.Duration(i) * time.Second), Action: "connect"}
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	for _, event := range []Event{
		{Time: now, Action: "put_begin", Offset: 64, Status: "完成"},
		{Time: now, Action: "put_finish", Status: "完成"},
		{Time: now, Action: "share_send", Name: "file.txt", Status: "完成"},
		{Time: now, Action: "get_finish", Status: "会话已取消"},
	} {
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	data.WriteString(`{"time":`)
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := loadAuditTail(path)
	if err != nil || len(events) != maxAuditEvents {
		t.Fatalf("restored %d events: %v", len(events), err)
	}
	if want := now.Add(14 * time.Second); !events[0].Time.Equal(want) {
		t.Errorf("first event: got %v, want %v", events[0].Time, want)
	}
	for i, want := range []string{"已返回上传位置", "SHA-256 校验通过，已存入服务端", "已投递收件箱，待收件人下载", "会话已取消"} {
		if got := events[len(events)-4+i].Status; got != want {
			t.Errorf("restored status: got %q, want %q", got, want)
		}
	}
}

func TestLoadAuditTailDoesNotReadEarlierThanByteLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	if err := encoder.Encode(Event{Time: time.Now(), Action: "outside-window"}); err != nil {
		t.Fatal(err)
	}
	data.Write(bytes.Repeat([]byte("x"), maxAuditRead))
	data.WriteByte('\n')
	if err := encoder.Encode(Event{Time: time.Now(), Action: "inside-window"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := loadAuditTail(path)
	if err != nil || len(events) != 1 || events[0].Action != "inside-window" {
		t.Fatalf("bounded window: got %+v, %v", events, err)
	}
}
