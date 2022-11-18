package telemetry

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

var prometheusDelta deltaCalculator

func PrometheusEndpoint(w http.ResponseWriter, req *http.Request) {
	metrics := GetMetrics()
	if len(metrics) == 0 {
		return
	}

	deltas := prometheusDelta.GetState("")
	sort.Sort(byName(metrics))
	prevName := ""
	for _, m := range metrics {
		if contains(OptStatsd, m.opts) {
			continue
		}

		if prevName != m.name {
			writeMetricHeader(w, m)
		}

		writeMetricValue(w, m, deltas.ValueFor(m))
		prevName = m.name
	}
}

func writeMetricHeader(w io.Writer, m *Metric) {
	w.Write([]byte(fmt.Sprintf("# TYPE %s %s\n", m.name, prometheusMetricType(m))))
}

func writeMetricValue(w io.Writer, m *Metric, value int64) {
	w.Write([]byte(fmt.Sprintf("%s{%s} %d\n", m.name, prometheusTags(m), value)))
}

type byName []*Metric

var _ sort.Interface = byName{}

func (b byName) Len() int {
	return len(b)
}

func (b byName) Less(i, j int) bool {
	return b[i].name < b[j].name
}

func (b byName) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func prometheusMetricType(m *Metric) string {
	if contains(OptGauge, m.opts) {
		return "gauge"
	}

	return "counter"
}

func prometheusTags(m *Metric) string {
	formattedTags := make([]string, 0, len(m.tags))
	for _, t := range m.tags {
		parts := strings.Split(t, ":")
		if len(parts) != 2 {
			continue
		}

		formattedTags = append(
			formattedTags,
			fmt.Sprintf(`%s="%s"`, parts[0], parts[1]),
		)
	}

	return strings.Join(formattedTags, ",")
}
