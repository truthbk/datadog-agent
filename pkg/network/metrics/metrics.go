package metrics

var (
	// MetricRuntimePrefix is the prefix of the metrics sent by the runtime security module
	MetricRuntimePrefix = "datadog.system_probe.network_tracer"

	// Perf buffer metrics

	// MetricPerfBufferLostWrite is the name of the metric used to count the number of lost events, as reported by a
	// dedicated count in kernel space
	// Tags: map, event_type
	MetricPerfBufferLostWrite = newRuntimeMetric(".perf_buffer.lost_events.write")
	// MetricPerfBufferLostRead is the name of the metric used to count the number of lost events, as reported in user
	// space by a perf buffer
	// Tags: map
	MetricPerfBufferLostRead = newRuntimeMetric(".perf_buffer.lost_events.read")

	// MetricPerfBufferEventsWrite is the name of the metric used to count the number of events written to a perf buffer
	// Tags: map, event_type
	MetricPerfBufferEventsWrite = newRuntimeMetric(".perf_buffer.events.write")
	// MetricPerfBufferEventsRead is the name of the metric used to count the number of events read from a perf buffer
	// Tags: map
	MetricPerfBufferEventsRead = newRuntimeMetric(".perf_buffer.events.read")
	// MetricPerfBufferEventsChannel is the name of the metric used to count the number of events read from a perf buffer
	// but currently buffered in a channel
	// Tags: map
	MetricPerfBufferEventsChannel = newRuntimeMetric(".perf_buffer.events.channel")

	// MetricPerfBufferBytesWrite is the name of the metric used to count the number of bytes written to a perf buffer
	// Tags: map, event_type
	MetricPerfBufferBytesWrite = newRuntimeMetric(".perf_buffer.bytes.write")
	// MetricPerfBufferBytesRead is the name of the metric used to count the number of bytes read from a perf buffer
	// Tags: map
	MetricPerfBufferBytesRead = newRuntimeMetric(".perf_buffer.bytes.read")
	// MetricPerfBufferSortingError is the name of the metric used to report events reordering issues.
	// Tags: map, event_type
	//MetricPerfBufferSortingError = newRuntimeMetric(".perf_buffer.sorting_error")
)

func newRuntimeMetric(name string) string {
	return MetricRuntimePrefix + name
}
