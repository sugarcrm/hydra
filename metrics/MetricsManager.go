package metrics

import (
	"github.com/sirupsen/logrus"
	"github.com/ory/hydra/metrics/telemetry"
	"github.com/ory/hydra/metrics/prometheus"
	"github.com/urfave/negroni"
)

type MetricsManager struct {
	handlers map[string]negroni.Handler
}

func NewMetricsManager(issuerURL string, databaseURL string, l logrus.FieldLogger, version, hash, buildTime string) *MetricsManager {
	mm := &MetricsManager{}
	mm.handlers = make(map[string]negroni.Handler)
	mm.handlers["telemetry"] = telemetry.NewMetricsHandler(issuerURL, databaseURL, l, version, hash, buildTime)
	mm.handlers["prometheus"] = prometheus.NewMetricsHandler(l, version, hash, buildTime)
	return mm
}

func (mm *MetricsManager) RegisterHandlers(n *negroni.Negroni){
	for _, handler := range mm.handlers {
		n.Use(handler)
	}
}
