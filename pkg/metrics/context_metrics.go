// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package metrics

import (
	"fmt"
	"math"

	"github.com/DataDog/datadog-agent/pkg/aggregator/ckey"
	"github.com/DataDog/datadog-agent/pkg/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type MetricIndex struct {
	inner uint64
}

func NewMetricIndex(mtype uint8, index uint32) MetricIndex {
	return MetricIndex{
		inner: uint64(mtype) | (uint64(index) << 8),
	}
}

func (mi MetricIndex) Type() MetricType {
	return MetricType(mi.inner & 0xff)
}

func init() {
	if NumMetricTypes > 255 {
		panic("NumMetricTypes too high")
	}
}

func (mi MetricIndex) Index() uint32 {
	return uint32(mi.inner >> 8)
}

// ContextMetrics stores all the metrics by context key
type ContextMetrics struct{
	inner *contextMetrics
}

type contextMetrics struct{
	indexes    map[ckey.ContextKey]MetricIndex
	gauges     []Gauge
	rates      []Rate
	counts     []Count
	mcounts    []MonotonicCount
	histograms []*Histogram
	historates []*Historate
	sets       []*Set
	counters   []*Counter
}

// MakeContextMetrics returns a new ContextMetrics
func MakeContextMetrics() ContextMetrics {
	return ContextMetrics{&contextMetrics{
		indexes: make(map[ckey.ContextKey]MetricIndex),
	}}
}

// AddSampleTelemetry counts number of new metrics added.
type AddSampleTelemetry struct {
	Total     telemetry.SimpleCounter
	Stateful  telemetry.SimpleCounter
	Stateless telemetry.SimpleCounter
}

// Inc should be called once for each new metric added to the map.
//
// isStateful should be the value returned by isStateful method for the new metric.
func (a *AddSampleTelemetry) Inc(isStateful bool) {
	a.Total.Inc()
	if isStateful {
		a.Stateful.Inc()
	} else {
		a.Stateless.Inc()
	}
}

// AddSample add a sample to the current ContextMetrics and initialize a new metrics if needed.
func (metrics *ContextMetrics) AddSample(contextKey ckey.ContextKey, sample *MetricSample, timestamp float64, interval int64, t *AddSampleTelemetry) error {
	m := metrics.inner

	if math.IsInf(sample.Value, 0) || math.IsNaN(sample.Value) {
		return fmt.Errorf("sample with value '%v'", sample.Value)
	}

	var mtype MetricType
	var index uint32

	if mi, ok := m.indexes[contextKey]; ok {
		mtype = mi.Type()
		index = mi.Index()
	} else {
		mtype = sample.Mtype
		var metric Metric

		switch sample.Mtype {
		case GaugeType:
			index = uint32(len(m.gauges))
			m.gauges = append(m.gauges, Gauge{})
		case RateType:
			index = uint32(len(m.rates))
			m.rates = append(m.rates, Rate{})
		case CountType:
			index = uint32(len(m.counts))
			m.counts = append(m.counts, Count{})
		case MonotonicCountType:
			index = uint32(len(m.mcounts))
			m.mcounts = append(m.mcounts, MonotonicCount{})
		case HistogramType:
			index = uint32(len(m.histograms))
			m.histograms = append(m.histograms, NewHistogram(interval))
		case HistorateType:
			index = uint32(len(m.historates))
			m.historates = append(m.historates, NewHistorate(interval))
		case SetType:
			index = uint32(len(m.sets))
			m.sets = append(m.sets, NewSet())
		case CounterType:
			index = uint32(len(m.counters))
			m.counters = append(m.counters, NewCounter(interval))
		default:
			err := fmt.Errorf("unknown sample metric type: %v", sample.Mtype)
			log.Error(err)
			return err
		}
		m.indexes[contextKey] = NewMetricIndex(uint8(sample.Mtype), index)

		// if t != nil {
		// 	t.Inc(metric.isStateful())
		// }
	}

	switch mtype {
	case GaugeType:
		m.gauges[index].addSample(sample, timestamp)
	case RateType:
		m.rates[index].addSample(sample, timestamp)
	case CountType:
		m.counts[index].addSample(sample, timestamp)
	case MonotonicCountType:
		m.mcounts[index].addSample(sample, timestamp)
	case HistogramType:
		m.histograms[index].addSample(sample, timestamp)
	case HistorateType:
		m.historates[index].addSample(sample, timestamp)
	case SetType:
		m.sets[index].addSample(sample, timestamp)
	case CounterType:
		m.counters[index].addSample(sample, timestamp)
	default:
		err := fmt.Errorf("unknown sample metric type: %v", sample.Mtype)
		log.Error(err)
		return err
	}

	return nil
}

func (metrics ContextMetrics) get(metricIndex MetricIndex) Metric {
	m := metrics.inner
	idx := metricIndex.Index()
	switch metricIndex.Type() {
	case GaugeType:
		return &m.gauges[idx]
	case RateType:
		return &m.rates[idx]
	case CountType:
		return &m.counts[idx]
	case MonotonicCountType:
		return &m.mcounts[idx]
	case HistogramType:
		return m.histograms[idx]
	case HistorateType:
		return m.historates[idx]
	case SetType:
		return m.sets[idx]
	case CounterType:
		return m.counters[idx]
	}
	return nil
}

// Flush flushes every metrics in the ContextMetrics.
// Returns the slice of Series and a map of errors by context key.
func (metrics ContextMetrics) Flush(timestamp float64) ([]*Serie, map[ckey.ContextKey]error) {
	var series []*Serie
	errors := make(map[ckey.ContextKey]error)

	for contextKey, metricIndex := range metrics.inner.indexes {
		series = flushToSeries(
			contextKey,
			metrics.get(metricIndex),
			timestamp,
			series,
			errors)
	}

	return series, errors
}

func flushToSeries(
	contextKey ckey.ContextKey,
	metric Metric,
	bucketTimestamp float64,
	series []*Serie,
	errors map[ckey.ContextKey]error) []*Serie {
	metricSeries, err := metric.flush(bucketTimestamp)

	if err == nil {
		for _, serie := range metricSeries {
			serie.ContextKey = contextKey
			series = append(series, serie)
		}
	} else {
		switch err.(type) {
		case NoSerieError:
			// this error happens in nominal conditions and shouldn't be returned
		default:
			errors[contextKey] = err
		}
	}
	return series
}

// aggregateContextMetricsByContextKey orders all Metric instances by context key,
// representing the result as calls to the given callbacks.  The `callback` parameter
// is called with each Metric in term, while `contextKeyChanged` is called after the
// last Metric with each context key is processed. The last argument of the callback is the index
// of the contextMetrics in contextMetricsCollection.
//  For example:
//     callback(key1, metric1, 0)
//     callback(key1, metric2, 1)
//     callback(key1, metric3, 2)
//     contextKeyChanged()
//     callback(key2, metric4, 0)
//     contextKeyChanged()
//     callback(key3, metric5, 0)
//     callback(key3, metric6, 1)
//     contextKeyChanged()
func aggregateContextMetricsByContextKey(
	contextMetricsCollection []ContextMetrics,
	callback func(ckey.ContextKey, Metric, int),
	contextKeyChanged func()) {
	for i := 0; i < len(contextMetricsCollection); i++ {
		for contextKey, metricIndex := range contextMetricsCollection[i].inner.indexes {
			callback(contextKey, contextMetricsCollection[i].get(metricIndex), i)

			// Find `contextKey` in the remaining contextMetrics
			for j := i + 1; j < len(contextMetricsCollection); j++ {
				contextMetrics := contextMetricsCollection[j]
				if metricIndex, found := contextMetrics.inner.indexes[contextKey]; found {
					callback(contextKey, contextMetrics.get(metricIndex), j)
					delete(contextMetrics.inner.indexes, contextKey)
				}
			}
			contextKeyChanged()
		}
	}
}
