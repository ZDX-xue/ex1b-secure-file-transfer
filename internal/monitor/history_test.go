package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var sampleStart = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func openHistory(t *testing.T, path string) *History {
	t.Helper()
	h, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func readWindow(t *testing.T, h *History, key string, end time.Time) Window {
	t.Helper()
	out, err := h.Window(key, end)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWindowUsesMeasuredDurationAndSkipsMissingIntervals(t *testing.T) {
	h := openHistory(t, "")
	h.Record(sampleStart, Counters{Received: 500, Online: 2})
	h.Record(sampleStart.Add(4*time.Second), Counters{Received: 900, Sent: 80, Online: 3, Incoming: 1})
	h.Record(sampleStart.Add(10*time.Second), Counters{Received: 1020, Sent: 200, Online: 4})
	h.Record(sampleStart.Add(45*time.Second), Counters{Received: 2020, Sent: 1000, Online: 5})
	h.Record(sampleStart.Add(50*time.Second), Counters{Received: 2120, Sent: 1100, Online: 6, Outgoing: 1})
	out := readWindow(t, h, "5m", sampleStart.Add(51*time.Second))
	if out.SinceMS != sampleStart.UnixMilli() || out.StepMS != 5000 || len(out.Points) != 3 {
		t.Fatalf("unexpected series: %+v", out)
	}
	if out.Totals != (Totals{620, 300}) || out.Peaks != (Peaks{Rates{100, 20}, 6}) {
		t.Fatalf("unexpected totals or peaks: %+v", out)
	}
	if out.Average != (Rates{rate(620, 15000), 20}) {
		t.Fatalf("unexpected duration-weighted rates: %+v", out.Average)
	}
	if out.Points[2].TimeMS != sampleStart.Add(50*time.Second).UnixMilli() ||
		out.Points[2].Input != 20 || out.Points[2].Outgoing != 1 {
		t.Fatalf("unexpected point after gap: %+v", out.Points[2])
	}
}

func TestFlushReloadAndCounterResetDoNotFabricateTraffic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	h := openHistory(t, path)
	h.Record(sampleStart, Counters{})
	h.Record(sampleStart.Add(5*time.Second), Counters{Received: 200, Sent: 40})
	if err := h.Flush(); err != nil {
		t.Fatal(err)
	}

	resumed := openHistory(t, path)
	resumed.Record(sampleStart.Add(10*time.Second), Counters{Received: 800, Sent: 90})
	resumed.Record(sampleStart.Add(15*time.Second), Counters{Received: 1000, Sent: 100})
	resumed.Record(sampleStart.Add(20*time.Second), Counters{Received: 0, Sent: 0})
	resumed.Record(sampleStart.Add(25*time.Second), Counters{Received: 50, Sent: 15})
	if err := resumed.Flush(); err != nil {
		t.Fatal(err)
	}
	out := readWindow(t, openHistory(t, path), "15m", sampleStart.Add(25*time.Second))
	if len(out.Points) != 3 || out.Totals != (Totals{450, 65}) {
		t.Fatalf("restart gap or reset was bridged: %+v", out)
	}
}

func TestClockReversalDoesNotReorderSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	h := openHistory(t, path)
	h.Record(sampleStart, Counters{})
	h.Record(sampleStart.Add(5*time.Second), Counters{Received: 100})
	h.Record(sampleStart.Add(10*time.Second), Counters{Received: 200})
	h.Record(sampleStart.Add(6*time.Second), Counters{Received: 400})
	h.Record(sampleStart.Add(11*time.Second), Counters{Received: 500})
	if err := h.Flush(); err != nil {
		t.Fatal(err)
	}
	out := readWindow(t, openHistory(t, path), "5m", sampleStart.Add(11*time.Second))
	if len(out.Points) != 2 || out.Totals.Received != 200 {
		t.Fatalf("clock reversal corrupted series: %+v", out)
	}
}

func TestRetentionAndDownsampling(t *testing.T) {
	h := openHistory(t, "")
	intervalCount := int(25 * time.Hour / (5 * time.Second))
	for i := 0; i <= intervalCount; i++ {
		h.Record(sampleStart.Add(time.Duration(i)*5*time.Second), Counters{Received: int64(i) * 10})
	}
	end := sampleStart.Add(25 * time.Hour)
	out := readWindow(t, h, "24h", end)
	if len(h.intervals) != 17280 || len(out.Points) != 288 || out.StepMS != 300000 {
		t.Fatalf("bad retention/downsampling: %d intervals, %d points", len(h.intervals), len(out.Points))
	}
	if out.Totals.Received != int64(len(h.intervals))*10 || out.Peaks.Input != 2 || out.Average.Input != 2 {
		t.Fatalf("downsampling changed summary: %v, %v, %v", out.Totals, out.Peaks, out.Average)
	}
	if _, err := h.Window("invalid", end); err == nil {
		t.Fatal("invalid window accepted")
	}
}

func TestRejectsCorruptSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	snapshot := `[{"start_ms":100,"end_ms":200},{"start_ms":190,"end_ms":250}]`
	if err := os.WriteFile(path, []byte(snapshot), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("overlapping historical observations were accepted")
	}
}
