package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type splitReader struct{ io.Reader }

func (r splitReader) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return r.Reader.Read(p)
}

func TestSplitAndCombinedFrames(t *testing.T) {
	var stream bytes.Buffer
	for _, id := range []uint64{1, 2} {
		frame := Frame{Header: Header{ID: id, Kind: "put", Name: "样本.txt"}, Body: []byte{0, 1, 255}}
		if err := Write(&stream, frame); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []uint64{1, 2} {
		got, err := Read(splitReader{&stream})
		if err != nil || got.ID != id || got.Name != "样本.txt" || !bytes.Equal(got.Body, []byte{0, 1, 255}) {
			t.Fatalf("unexpected frame: %#v %v", got, err)
		}
	}
}

func TestLengthBoundsAndTruncation(t *testing.T) {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], MaxHeader+1)
	if _, err := Read(bytes.NewReader(prefix[:])); err == nil {
		t.Fatal("oversize heading accepted")
	}
	var stream bytes.Buffer
	if err := Write(&stream, Frame{Header: Header{ID: 7, Kind: "reply"}, Body: []byte("payload")}); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(stream.Bytes()[:stream.Len()-1])); err == nil {
		t.Fatal("truncated body accepted")
	}
}

func TestMeasuredHeaderMatchesLengthPrefix(t *testing.T) {
	var encoded bytes.Buffer
	body := []byte("file content")
	headerSize, err := WriteMeasured(&encoded, Frame{
		Header: Header{ID: 8, Kind: "put_chunk", Offset: ChunkSize},
		Body:   body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := int(binary.BigEndian.Uint32(encoded.Bytes()[:4])); want != headerSize ||
		encoded.Len() != 4+headerSize+len(body) {
		t.Fatalf("reported %d header bytes, prefix specifies %d, frame is %d bytes", headerSize, want, encoded.Len())
	}
	frame, err := Read(splitReader{&encoded})
	if err != nil || frame.HeaderBytes != headerSize || !bytes.Equal(frame.Body, body) {
		t.Fatalf("decoded header %d, error %v", frame.HeaderBytes, err)
	}
}
