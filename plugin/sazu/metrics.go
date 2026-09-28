package sazu

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// updatesTotal counts UPDATE transactions by outcome: the response code
// and the SAZU status code ("" when there is none).
var updatesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "sazu",
	Name:      "updates_total",
	Help:      "Counter of UPDATE transactions by response code and SAZU status code.",
}, []string{"server", "rcode", "status"})
