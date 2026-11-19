package registry

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type registryMetrics struct {
	registry           *prometheus.Registry
	httpRequests       *prometheus.CounterVec
	httpRequestLatency *prometheus.HistogramVec
	indexBuilds        *prometheus.CounterVec
	indexBuildLatency  *prometheus.HistogramVec
	indexRetries       *prometheus.CounterVec
}

func newRegistryMetrics() *registryMetrics {
	m := &registryMetrics{
		registry: prometheus.NewRegistry(),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "apk_registry_http_requests_total",
			Help: "Total number of HTTP requests handled.",
		}, []string{"method", "route", "status"}),
		httpRequestLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "apk_registry_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route", "status"}),
		indexBuilds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "apk_registry_index_builds_total",
			Help: "Total number of APK index build attempts by architecture and outcome.",
		}, []string{"architecture", "outcome"}),
		indexBuildLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "apk_registry_index_build_duration_seconds",
			Help:    "APK index build duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"architecture", "outcome"}),
		indexRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "apk_registry_index_retries_total",
			Help: "Total number of APK index build retries by architecture.",
		}, []string{"architecture"}),
	}
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.httpRequests,
		m.httpRequestLatency,
		m.indexBuilds,
		m.indexBuildLatency,
		m.indexRetries,
	)
	return m
}

func (m *registryMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *registryMetrics) observeRequest(method, route string, status int, duration time.Duration) {
	statusLabel := strconv.Itoa(status)
	m.httpRequests.WithLabelValues(method, route, statusLabel).Inc()
	m.httpRequestLatency.WithLabelValues(method, route, statusLabel).Observe(duration.Seconds())
}

func (m *registryMetrics) observeIndexBuild(architecture, outcome string, duration time.Duration) {
	m.indexBuilds.WithLabelValues(architecture, outcome).Inc()
	m.indexBuildLatency.WithLabelValues(architecture, outcome).Observe(duration.Seconds())
}

func (m *registryMetrics) observeIndexRetry(architecture string) {
	m.indexRetries.WithLabelValues(architecture).Inc()
}
