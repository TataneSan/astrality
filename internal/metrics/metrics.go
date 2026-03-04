package metrics

import "github.com/prometheus/client_golang/prometheus"

type Registry struct {
	NodeCount       prometheus.Gauge
	HeartbeatsTotal *prometheus.CounterVec
	RequestsTotal   *prometheus.CounterVec
}

func New() *Registry {
	nodeCount := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "astrality_nodes_total",
		Help: "Known nodes",
	})
	heartbeats := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "astrality_heartbeats_total",
		Help: "Heartbeats accepted",
	}, []string{"status"})
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "astrality_http_requests_total",
		Help: "HTTP requests",
	}, []string{"path", "status"})

	prometheus.MustRegister(nodeCount, heartbeats, requests)
	return &Registry{
		NodeCount:       nodeCount,
		HeartbeatsTotal: heartbeats,
		RequestsTotal:   requests,
	}
}
