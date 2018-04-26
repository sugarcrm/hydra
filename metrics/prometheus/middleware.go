package prometheus

import (
	"net/http"
	"github.com/sirupsen/logrus"
	"time"
)

type PrometheusHandler struct {
	prometheusMetrics *Metrics
}

func NewMetricsHandler(l logrus.FieldLogger, version, hash, buildTime string) *PrometheusHandler {
	l.Info("Setting up Prometheus metrics")
	return &PrometheusHandler{
		prometheusMetrics: NewMetrics(version, hash, buildTime),
	}
}

func (pmm *PrometheusHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func(start time.Time) {
		pmm.prometheusMetrics.Counter.WithLabelValues(r.URL.Path).Inc()
		pmm.prometheusMetrics.ResponseTime.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}(time.Now())
	next(rw, r)
}
