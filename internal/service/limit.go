package service

import (
	"context"
	"sync"
	"time"

	"ex1b/internal/wire"
)

// Every certificate-mapped account shares one bucket across uploads, downloads
// and sessions. A block-sized burst prevents throttling an isolated small file.
type limiter struct {
	mu     sync.Mutex
	last   time.Time
	credit float64
	rate   float64
}

func newLimiter(rate int64) *limiter {
	return &limiter{last: time.Now(), credit: wire.ChunkSize, rate: float64(rate)}
}

func (l *limiter) Wait(ctx context.Context, count int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := time.Now()
		l.credit = min(wire.ChunkSize, l.credit+now.Sub(l.last).Seconds()*l.rate)
		l.last = now
		if l.credit >= float64(count) {
			l.credit -= float64(count)
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((float64(count)-l.credit)/l.rate*float64(time.Second)) + time.Millisecond
		l.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
