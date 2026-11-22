package webapp

import (
	"context"
	"log"
	"time"

	"ex1b/internal/monitor"
)

func (g *gateway) sampleTraffic(ctx context.Context) {
	record := func() {
		counters, online := g.service.TrafficSnapshot()
		g.history.Record(time.Now(), monitor.Counters{
			Received: counters.Received, Sent: counters.Sent, Online: online,
			Incoming: counters.Incoming, Outgoing: counters.Outgoing,
		})
	}
	save := func() {
		if err := g.history.Flush(); err != nil {
			log.Printf("保存监控流量历史: %v", err)
		}
	}
	record()
	sample := time.NewTicker(5 * time.Second)
	flush := time.NewTicker(30 * time.Second)
	defer sample.Stop()
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			record()
			save()
			return
		case <-sample.C:
			record()
		case <-flush.C:
			save()
		}
	}
}
