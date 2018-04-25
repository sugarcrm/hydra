package prometheus

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Counter      *prometheus.CounterVec
	ResponseTime *prometheus.HistogramVec
}

func NewMetrics(version, hash, buildTime string) *Metrics {
	labels := map[string]string{
		"version":   version,
		"hash":      hash,
		"buildTime": buildTime,
	}
	pm := &Metrics{
		Counter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "sts_requests_total",
				Help:        "Secure token service requests served per endpoint",
				ConstLabels: labels,
			},
			[]string{"endpoint"},
		),
		ResponseTime: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:        "sts_response_time_seconds",
				Help:        "Secure token service response time",
				ConstLabels: labels,
			},
			[]string{"endpoint"},
		),
	}
	prometheus.Register(pm.Counter)
	prometheus.Register(pm.ResponseTime)
	return pm
}
