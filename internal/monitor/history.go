// Package monitor retains recent observations of cumulative service counters.
package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	retention    = 24 * time.Hour
	maxGap       = 15 * time.Second
	maxIntervals = int(retention/(5*time.Second)) + 256
	maxFileBytes = 4 << 20
)

type Counters struct {
	Received, Sent             int64
	Online, Incoming, Outgoing int
}

type observation struct {
	At time.Time
	Counters
}

// An interval represents bytes measured between two counter observations.
// Its endpoints are persisted so gaps are preserved across process restarts.
type interval struct {
	StartMS  int64 `json:"start_ms"`
	EndMS    int64 `json:"end_ms"`
	Received int64 `json:"received"`
	Sent     int64 `json:"sent"`
	Online   int   `json:"online"`
	Incoming int   `json:"incoming"`
	Outgoing int   `json:"outgoing"`
}

type History struct {
	path string

	mu        sync.RWMutex
	intervals []interval
	baseline  observation
	revision  uint64

	diskMu  sync.Mutex
	written uint64
}

type Point struct {
	TimeMS   int64   `json:"time_ms"`
	Input    float64 `json:"input"`
	Output   float64 `json:"output"`
	Online   int     `json:"online"`
	Incoming int     `json:"incoming"`
	Outgoing int     `json:"outgoing"`
}

type Totals struct {
	Received int64 `json:"received"`
	Sent     int64 `json:"sent"`
}

type Rates struct {
	Input  float64 `json:"input"`
	Output float64 `json:"output"`
}

type Peaks struct {
	Rates
	Online int `json:"online"`
}

type Window struct {
	Range   string  `json:"range"`
	StartMS int64   `json:"start_ms"`
	EndMS   int64   `json:"end_ms"`
	StepMS  int64   `json:"step_ms"`
	SinceMS int64   `json:"since_ms"`
	Points  []Point `json:"points"`
	Totals  Totals  `json:"totals"`
	Peaks   Peaks   `json:"peaks"`
	Average Rates   `json:"average"`
}

// Open loads an existing history without adopting its final counters as the
// new process's baseline. An empty path enables an in-memory history.
func Open(path string) (*History, error) {
	h := &History{path: path}
	if path == "" {
		return h, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > maxFileBytes {
		return nil, errors.New("流量历史文件格式或大小无效")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&h.intervals); err != nil || decoder.Decode(new(any)) != io.EOF || len(h.intervals) > maxIntervals {
		return nil, errors.New("流量历史文件无法读取")
	}
	var previousEnd int64
	for _, sample := range h.intervals {
		if sample.StartMS <= 0 || sample.StartMS < previousEnd || sample.EndMS <= sample.StartMS ||
			sample.EndMS-sample.StartMS > maxGap.Milliseconds() || sample.Received < 0 || sample.Sent < 0 ||
			sample.Online < 0 || sample.Incoming < 0 || sample.Outgoing < 0 {
			return nil, errors.New("流量历史包含无效采样")
		}
		previousEnd = sample.EndMS
	}
	return h, nil
}

// Record samples actual cumulative counters. Missed ticks, a clock reversal,
// or a counter reset all start a new baseline without manufacturing a rate.
func (h *History) Record(at time.Time, counters Counters) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if at.UnixMilli() <= 0 || counters.Received < 0 || counters.Sent < 0 ||
		counters.Online < 0 || counters.Incoming < 0 || counters.Outgoing < 0 {
		h.baseline = observation{}
		return
	}
	previous := h.baseline
	h.baseline = observation{At: at, Counters: counters}
	end := at.UnixMilli()
	cutoff := at.Add(-retention).UnixMilli()
	first := sort.Search(len(h.intervals), func(i int) bool { return h.intervals[i].EndMS > cutoff })
	last := sort.Search(len(h.intervals), func(i int) bool { return h.intervals[i].EndMS > end })
	if first > 0 || last < len(h.intervals) {
		h.intervals = h.intervals[first:last]
		h.revision++
	}
	start := previous.At.UnixMilli()
	if previous.At.IsZero() || end <= start || end-start > maxGap.Milliseconds() ||
		counters.Received < previous.Received || counters.Sent < previous.Sent {
		return
	}
	if n := len(h.intervals); n > 0 && start < h.intervals[n-1].EndMS {
		return
	}
	if len(h.intervals) == maxIntervals {
		h.intervals = h.intervals[1:]
	}
	h.intervals = append(h.intervals, interval{
		StartMS: start, EndMS: end, Received: counters.Received - previous.Received, Sent: counters.Sent - previous.Sent,
		Online: counters.Online, Incoming: counters.Incoming, Outgoing: counters.Outgoing,
	})
	h.revision++
}

func (h *History) Window(key string, now time.Time) (Window, error) {
	var duration, step time.Duration
	switch key {
	case "5m":
		duration, step = 5*time.Minute, 5*time.Second
	case "15m":
		duration, step = 15*time.Minute, 5*time.Second
	case "1h":
		duration, step = time.Hour, 15*time.Second
	case "24h":
		duration, step = 24*time.Hour, 5*time.Minute
	default:
		return Window{}, errors.New("不支持的流量时间范围")
	}
	out := Window{
		Range: key, StartMS: now.Add(-duration).UnixMilli(), EndMS: now.UnixMilli(), StepMS: step.Milliseconds(),
		Points: make([]Point, 0, int(duration/step)+1),
	}
	h.mu.RLock()
	defer h.mu.RUnlock()

	// A query boundary cutting through a sample cannot determine how many
	// bytes were on either side. Only complete observed intervals are counted.
	first := sort.Search(len(h.intervals), func(i int) bool { return h.intervals[i].StartMS >= out.StartMS })
	var bucket Point
	var bucketID, bucketMS, observedMS int64
	var received, sent int64
	for _, sample := range h.intervals[first:] {
		if sample.EndMS > out.EndMS {
			break
		}
		if out.SinceMS == 0 {
			out.SinceMS = sample.StartMS
		}
		elapsed := sample.EndMS - sample.StartMS
		observedMS += elapsed
		out.Totals.Received += sample.Received
		out.Totals.Sent += sample.Sent
		out.Peaks.Input = max(out.Peaks.Input, rate(sample.Received, elapsed))
		out.Peaks.Output = max(out.Peaks.Output, rate(sample.Sent, elapsed))
		out.Peaks.Online = max(out.Peaks.Online, sample.Online)
		id := (sample.EndMS - 1) / out.StepMS
		if bucketMS > 0 && id != bucketID {
			bucket.Input, bucket.Output = rate(received, bucketMS), rate(sent, bucketMS)
			out.Points = append(out.Points, bucket)
			bucket, bucketMS, received, sent = Point{}, 0, 0, 0
		}
		bucketID = id
		bucketMS += elapsed
		received += sample.Received
		sent += sample.Sent
		bucket.TimeMS = sample.EndMS
		bucket.Online = max(bucket.Online, sample.Online)
		bucket.Incoming = max(bucket.Incoming, sample.Incoming)
		bucket.Outgoing = max(bucket.Outgoing, sample.Outgoing)
	}
	if bucketMS > 0 {
		bucket.Input, bucket.Output = rate(received, bucketMS), rate(sent, bucketMS)
		out.Points = append(out.Points, bucket)
		out.Average = Rates{Input: rate(out.Totals.Received, observedMS), Output: rate(out.Totals.Sent, observedMS)}
	}
	return out, nil
}

func rate(bytes, millis int64) float64 {
	return float64(bytes) * 1000 / float64(millis)
}

// Flush replaces the snapshot atomically. A failed write leaves both the
// prior snapshot and the pending in-memory observations available to retry.
func (h *History) Flush() error {
	if h.path == "" {
		return nil
	}
	h.diskMu.Lock()
	defer h.diskMu.Unlock()
	h.mu.RLock()
	revision := h.revision
	if revision == h.written {
		h.mu.RUnlock()
		return nil
	}
	intervals := append([]interval{}, h.intervals...)
	h.mu.RUnlock()
	tmp, err := os.CreateTemp(filepath.Dir(h.path), ".traffic-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	writeErr := json.NewEncoder(tmp).Encode(intervals)
	if err := errors.Join(writeErr, tmp.Sync(), tmp.Close()); err != nil {
		return fmt.Errorf("保存流量历史: %w", err)
	}
	if err := os.Rename(tmp.Name(), h.path); err != nil {
		return fmt.Errorf("替换流量历史: %w", err)
	}
	h.written = revision
	return nil
}
