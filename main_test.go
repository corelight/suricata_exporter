package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var (
	descStringRe   = regexp.MustCompile("fqName: \"([^\"]+)\"")
	sampleCounters = map[string]interface{}{
		"message": map[string]interface{}{
			"uptime":  123.0,
			"threads": map[string]interface{}{},
			"detect": map[string]interface{}{
				"engines": []interface{}{
					map[string]interface{}{
						"id":           0.0,
						"last_reload":  "2021-12-08T11:28:38.980499+0100",
						"rules_loaded": 42.0,
						"rules_failed": 18.0,
					},
				},
			},
		}}
)

type testMetric struct {
	fqName string
	type_  string
	value  float64
	labels map[string]string
}

// Aggregate metrics by fqName and return them as testMetric instances
func aggregateMetrics(metrics []prometheus.Metric) map[string][]testMetric {
	result := make(map[string][]testMetric)
	for _, m := range metrics {
		dm := &dto.Metric{}
		m.Write(dm)
		tm := testMetricFromMetric(m)
		// fmt.Printf("%+v\n", tm)

		result[tm.fqName] = append(result[tm.fqName], tm)
	}
	return result
}

// Helper converting *prometheus.Metric to something easier usable for testing.
func testMetricFromMetric(m prometheus.Metric) testMetric {
	desc := m.Desc()
	dm := &dto.Metric{}
	m.Write(dm)

	var type_ string
	var value float64
	if dm.Counter != nil {
		type_ = "counter"
		value = dm.Counter.GetValue()
	} else if dm.Gauge != nil {
		type_ = "gauge"
		value = dm.Gauge.GetValue()
	} else {
		panic(fmt.Sprintf("unknown type: %v", desc.String()))
	}

	labels := make(map[string]string)

	// Iterate over LabelPairs
	for _, lp := range dm.GetLabel() {
		labels[*lp.Name] = *lp.Value
	}

	matches := descStringRe.FindStringSubmatch(desc.String())

	return testMetric{
		fqName: matches[1],
		type_:  type_,
		value:  value,
		labels: labels,
	}
}

// Call produceMetrics with the given data and collect all produced metrics.
func produceMetricsHelper(data map[string]interface{}) []prometheus.Metric {
	ch := make(chan prometheus.Metric)
	finished := make(chan bool)

	go func() {
		produceMetrics(ch, data)
		finished <- true
	}()

	metrics := []prometheus.Metric{}
	done := false

	for !done {
		select {
		case m := <-ch:
			metrics = append(metrics, m)
		case <-finished:
			done = true
		}
	}

	return metrics
}

func TestProduceMetricsRules(t *testing.T) {

	metrics := produceMetricsHelper(sampleCounters)

	found_rules_loaded := false
	found_rules_failed := false

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "suricata_detect_engine_rules_loaded") {
			found_rules_loaded = true
			dm := &dto.Metric{}
			m.Write(dm)

			expected := `label:<name:"id" value:"0" > gauge:<value:42 > `
			if dm.String() != expected {
				t.Errorf("Unexpected rules_loaded metric: expected=%q have=%q", expected, dm.String())
			}
		} else if strings.Contains(m.Desc().String(), "suricata_detect_engine_rules_failed") {
			dm := &dto.Metric{}
			m.Write(dm)
			found_rules_failed = true
			expected := `label:<name:"id" value:"0" > gauge:<value:18 > `
			if dm.String() != expected {
				t.Errorf("Unexpected rules_loaded metric: expected=%q have=%q", expected, dm.String())
			}

		}
	}

	if !found_rules_loaded {
		t.Errorf("Failed to find suricata_detect_engine_rules_loaded metric")
	}
	if !found_rules_failed {
		t.Errorf("Failed to find suricata_detect_engine_rules_loaded metric")
	}
}

func TestProduceMetricsLastReload(t *testing.T) {

	metrics := produceMetricsHelper(sampleCounters)

	found_last_reload := false

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "suricata_detect_engine_last_reload") {
			found_last_reload = true
			dm := &dto.Metric{}
			m.Write(dm)

			expected := `label:<name:"id" value:"0" > gauge:<value:1.638959318e+09 > `
			if dm.String() != expected {
				t.Errorf("Unexpected rules_loaded metric: expected=%q have=%q", expected, dm.String())
			}
		}
	}

	if !found_last_reload {
		t.Errorf("Failed to find suricata_detect_engine_last_reload_timestamp_seconds metric")
	}
}

func TestDump604AFPacket(t *testing.T) {
	data, err := ioutil.ReadFile("./testdata/dump-counters-6.0.4-afpacket.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]interface{}
	json.Unmarshal(data, &counters)

	metrics := produceMetricsHelper(counters)
	agged := aggregateMetrics(metrics)

	tms, ok := agged["suricata_capture_kernel_packets_total"] // test metrics
	if !ok {
		t.Errorf("Failed to find suricata_capture_kernel_packets metrics")
	}

	if len(tms) != 8 {
		t.Errorf("Unexpected number of suricata_kernel_packets metrics: %v", len(tms))
	}

	tns := make([]string, len(tms)) // thread names
	for i, tm := range tms {
		tns[i] = tm.labels["thread"]
	}

	sort.Strings(tns)
	threadNames := fmt.Sprintf("%v", tns)
	if threadNames != "[W#01-wlp0s20f3 W#02-wlp0s20f3 W#03-wlp0s20f3 W#04-wlp0s20f3 W#05-wlp0s20f3 W#06-wlp0s20f3 W#07-wlp0s20f3 W#08-wlp0s20f3]" {
		t.Errorf("Unexpected threadNames: %v", threadNames)
	}
}

func TestDump604Netmap(t *testing.T) {
	data, err := ioutil.ReadFile("./testdata/dump-counters-6.0.4-netmap.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]interface{}
	json.Unmarshal(data, &counters)

	metrics := produceMetricsHelper(counters)
	// This is a bit dumb because once more metrics are added this isn't
	// useful, but testing individual metrics is a bit annoying.
	if len(metrics) != 233 {
		t.Errorf("Expected 233 metrics, got %d", len(metrics))
	}
}

func TestDump604Napatech(t *testing.T) {
	data, err := ioutil.ReadFile("./testdata/dump-counters-6.0.4-napatech.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]interface{}
	json.Unmarshal(data, &counters)

	metrics := produceMetricsHelper(counters)
	agged := aggregateMetrics(metrics)

	if _, ok := agged["suricata_napatech_packets_total"]; !ok {
		t.Errorf("Missing suricata_napatech_packets_total metric")
	}
	if _, ok := agged["suricata_napatech_bytes_total"]; !ok {
		t.Errorf("Missing suricata_napatech_bytes_total metric")
	}
	if _, ok := agged["suricata_napatech_overflow_drop_bytes_total"]; !ok {
		t.Errorf("Missing suricata_napatech_overflow_drop_bytes_total metric")
	}
	if _, ok := agged["suricata_napatech_overflow_drop_packets_total"]; !ok {
		t.Errorf("Missing suricata_napatech_overflow_drop_packets_total metric")
	}
	if _, ok := agged["suricata_napatech_dispatch_host_packets_total"]; !ok {
		t.Errorf("Missing suricata_napatech_dispatch_host_packets_total metric")
	}
	if _, ok := agged["suricata_napatech_dispatch_host_bytes_total"]; !ok {
		t.Errorf("Missing suricata_napatech_dispatch_host_packets_total metric")
	}
	if _, ok := agged["suricata_napatech_dispatch_drop_packets_total"]; !ok {
		t.Errorf("Missing suricata_napatech_dispatch_drop_packets_total metric")
	}
	if _, ok := agged["suricata_napatech_dispatch_drop_bytes_total"]; !ok {
		t.Errorf("Missing suricata_napatech_dispatch_drop_packets_total metric")
	}
}

func TestDump700AFPacket(t *testing.T) {
	data, err := ioutil.ReadFile("./testdata/dump-counters-7.0.0-afpacket.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]interface{}
	json.Unmarshal(data, &counters)

	metrics := produceMetricsHelper(counters)
	agged := aggregateMetrics(metrics)

	tms, ok := agged["suricata_capture_afpacket_poll_results_total"] // test metrics
	if !ok {
		t.Errorf("Failed to find suricata_capture_afpacket_poll_results_total metrics")
	}

	// 2 threads, 4 results
	if len(tms) != 8 {
		t.Errorf("Unexpected number of suricata_capture_afpacket_poll_results_total metrics: %v", len(tms))
	}

	tms, ok = agged["suricata_detect_alerts_total"] // test metrics
	if !ok {
		t.Errorf("Failed to find detect_alerts_total metrics")
	}

	if len(tms) != 2 {
		t.Errorf("Unexpected number of suricata_detect_alerts_total metrics: %v", len(tms))
	}

	tms, ok = agged["suricata_detect_alert_queue_overflows_total"] // test metrics
	if !ok {
		t.Errorf("Failed to find detect_alerts_queue_overflows_total metrics")
	}

	if len(tms) != 2 {
		t.Errorf("Unexpected number of suricata_detect_alerts_queue_overflows_total metrics: %v", len(tms))
	}
}
