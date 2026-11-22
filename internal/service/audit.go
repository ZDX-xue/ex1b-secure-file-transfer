package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const (
	maxAuditEvents = 160
	maxAuditRead   = 512 << 10
)

func appendAuditEvent(events []Event, event Event) []Event {
	if len(events) == maxAuditEvents {
		copy(events, events[1:])
		events = events[:maxAuditEvents-1]
	}
	return append(events, event)
}

func transferAuditStatus(action, name string, offset int64, alreadyUploaded bool) string {
	switch action {
	case "put_begin":
		if alreadyUploaded {
			return "文件已在服务端入库"
		}
		if offset > 0 {
			return "已确认续传位置"
		}
		return "已受理，等待上传文件"
	case "put_finish":
		return "SHA-256 校验通过，已存入服务端"
	case "share_send":
		if name != "" {
			return "已投递收件箱，待收件人下载"
		}
		return "文字消息已投递收件箱"
	case "get_begin":
		return "已返回文件信息，准备下载"
	case "get_finish":
		return "接收端已确认文件完整性"
	default:
		return "完成"
	}
}

// loadAuditTail restores the displayed audit window without scanning the full
// append-only file. A partial line at the start of the window is discarded.
func loadAuditTail(path string) ([]Event, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("审计日志不是普通文件")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	start := max(0, info.Size()-maxAuditRead)
	data, err := io.ReadAll(io.NewSectionReader(file, start, info.Size()-start))
	if err != nil {
		return nil, err
	}
	if start > 0 {
		_, data, _ = bytes.Cut(data, []byte("\n"))
	}
	var events []Event
	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte("\n"))
		var event Event
		if json.Unmarshal(line, &event) != nil || event.Time.IsZero() || event.Action == "" {
			continue
		}
		if event.Status == "完成" {
			if event.Action == "put_begin" && event.Offset > 0 {
				// A legacy entry exposes an offset but cannot say whether the
				// existing file was already published or only partially written.
				event.Status = "已返回上传位置"
			} else {
				event.Status = transferAuditStatus(event.Action, event.Name, event.Offset, false)
			}
		}
		events = appendAuditEvent(events, event)
	}
	return events, nil
}
