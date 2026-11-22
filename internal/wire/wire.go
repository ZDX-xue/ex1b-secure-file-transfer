// Package wire defines the bounded EX1B frames carried on a TLS byte stream.
package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	Version   = 1
	MaxHeader = 8 * 1024
	MaxBody   = 128 * 1024
	ChunkSize = 32 * 1024
	MaxFile   = 128 * 1024 * 1024
)

type Header struct {
	Version int    `json:"version"`
	ID      uint64 `json:"id"`
	Kind    string `json:"kind"`
	BodyLen int    `json:"body_len"`
	Name    string `json:"name,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Offset  int64  `json:"offset,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Done    bool   `json:"done,omitempty"`
	Error   string `json:"error,omitempty"`
	User    string `json:"user,omitempty"`
	Role    string `json:"role,omitempty"`
	Session string `json:"session,omitempty"`
	Rate    int64  `json:"rate,omitempty"`
	TLS     string `json:"tls,omitempty"`
}

type Frame struct {
	Header
	Body []byte
}

func Read(reader io.Reader) (Frame, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return Frame{}, err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || size > MaxHeader {
		return Frame{}, fmt.Errorf("报文头长度超出限制")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return Frame{}, err
	}
	var frame Frame
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&frame.Header); err != nil || dec.Decode(new(any)) != io.EOF {
		return Frame{}, fmt.Errorf("报文头格式无效")
	}
	if frame.Version != Version || frame.ID == 0 || frame.Kind == "" || frame.BodyLen < 0 || frame.BodyLen > MaxBody {
		return Frame{}, fmt.Errorf("报文版本、编号或数据长度无效")
	}
	if frame.BodyLen > 0 {
		frame.Body = make([]byte, frame.BodyLen)
		if _, err := io.ReadFull(reader, frame.Body); err != nil {
			return Frame{}, err
		}
	}
	return frame, nil
}

func Write(writer io.Writer, frame Frame) error {
	frame.Version = Version
	frame.BodyLen = len(frame.Body)
	if frame.ID == 0 || frame.Kind == "" || frame.BodyLen > MaxBody {
		return fmt.Errorf("无法发送超限或无编号的报文")
	}
	header, err := json.Marshal(frame.Header)
	if err != nil || len(header) > MaxHeader {
		return fmt.Errorf("无法编码报文头")
	}
	data := make([]byte, 4+len(header)+len(frame.Body))
	binary.BigEndian.PutUint32(data[:4], uint32(len(header)))
	copy(data[4:], header)
	copy(data[4+len(header):], frame.Body)
	n, err := writer.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
