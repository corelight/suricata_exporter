package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var (
	descStringRe   = regexp.MustCompile("fqName: \"([^\"]+)\"")
	sampleCounters = map[string]any{
		"message": map[string]any{
			"uptime":  123.0,
			"threads": map[string]any{},
			"detect": map[string]any{
				"engines": []any{
					map[string]any{
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
		err := m.Write(dm)
		if err != nil {
			return nil
		}
		tm := testMetricFromMetric(m)
		// fmt.Printf("%+v\n", tm)

		result[tm.fqName] = append(result[tm.fqName], tm)
	}
	return result
}

func sortedThreadNames(tms []testMetric) string {
	tns := make([]string, len(tms)) // thread names
	for i, tm := range tms {
		tns[i] = tm.labels["thread"]
	}

	sort.Strings(tns)

	return fmt.Sprintf("%v", tns)
}

// Helper converting *prometheus.Metric to something easier usable for testing.
func testMetricFromMetric(m prometheus.Metric) testMetric {
	desc := m.Desc()
	dm := &dto.Metric{}
	err := m.Write(dm)
	if err != nil {
		return testMetric{}
	}
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
	if dm.GetLabel() != nil {
		for _, lp := range dm.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
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
func produceMetricsHelper(data map[string]any) []prometheus.Metric {
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

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func testRulesMetricGauge(t *testing.T, tm *testMetric, value float64) {
	t.Helper()
	if tm.type_ != "gauge" {
		t.Errorf("rules_loaded not a gauge, is %v", tm.type_)
	}

	if !almostEqual(tm.value, value) {
		t.Errorf("wrong gauge value %+v", tm.value)
	}

	if len(tm.labels) != 1 {
		t.Errorf("expected single rules loaded label")
	}

	if !reflect.DeepEqual(tm.labels, map[string]string{"id": "0"}) {
		t.Errorf("unexpected labels %+v", tm.labels)
	}
}

func TestProduceMetricsRules(t *testing.T) {

	metrics := produceMetricsHelper(sampleCounters)

	foundRulesLoaded := false
	foundRulesFailed := false

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "suricata_detect_engine_rules_loaded") {
			foundRulesLoaded = true
			tm := testMetricFromMetric(m)
			testRulesMetricGauge(t, &tm, 42.0)
		} else if strings.Contains(m.Desc().String(), "suricata_detect_engine_rules_failed") {
			foundRulesFailed = true
			tm := testMetricFromMetric(m)
			testRulesMetricGauge(t, &tm, 18.0)
		}
	}

	if !foundRulesLoaded {
		t.Errorf("Failed to find suricata_detect_engine_rules_loaded metric")
	}
	if !foundRulesFailed {
		t.Errorf("Failed to find suricata_detect_engine_rules_loaded metric")
	}
}

func TestProduceMetricsLastReload(t *testing.T) {

	metrics := produceMetricsHelper(sampleCounters)

	foundLastReload := false

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "suricata_detect_engine_last_reload") {
			foundLastReload = true
			tm := testMetricFromMetric(m)
			testRulesMetricGauge(t, &tm, 1638959318.0)
		}
	}

	if !foundLastReload {
		t.Errorf("Failed to find suricata_detect_engine_last_reload_timestamp_seconds metric")
	}
}

func TestDump604AFPacket(t *testing.T) {
	data, err := os.ReadFile("./testdata/dump-counters-6.0.4-afpacket.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]any
	err = json.Unmarshal(data, &counters)
	if err != nil {
		t.Error(err)
	}

	metrics := produceMetricsHelper(counters)
	agged := aggregateMetrics(metrics)

	tms, ok := agged["suricata_capture_kernel_packets_total"] // test metrics
	if !ok {
		t.Errorf("Failed to find suricata_capture_kernel_packets metrics")
	}

	if len(tms) != 8 {
		t.Errorf("Unexpected number of suricata_kernel_packets metrics: %v", len(tms))
	}

	threadNames := sortedThreadNames(tms)
	if threadNames != "[W#01-wlp0s20f3 W#02-wlp0s20f3 W#03-wlp0s20f3 W#04-wlp0s20f3 W#05-wlp0s20f3 W#06-wlp0s20f3 W#07-wlp0s20f3 W#08-wlp0s20f3]" {
		t.Errorf("Unexpected threadNames: %v", threadNames)
	}
}

func TestDump604Netmap(t *testing.T) {
	data, err := os.ReadFile("./testdata/dump-counters-6.0.4-netmap.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]any
	err = json.Unmarshal(data, &counters)
	if err != nil {
		t.Error(err)
	}

	metrics := produceMetricsHelper(counters)
	// This is a bit dumb because once more metrics are added this isn't
	// useful, but testing individual metrics is a bit annoying.
	if len(metrics) != 233 {
		t.Errorf("Expected 233 metrics, got %d", len(metrics))
	}
}

func TestDump604Napatech(t *testing.T) {
	data, err := os.ReadFile("./testdata/dump-counters-6.0.4-napatech.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]any
	err = json.Unmarshal(data, &counters)
	if err != nil {
		t.Error(err)
	}

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
	data, err := os.ReadFile("./testdata/dump-counters-7.0.0-afpacket.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]any
	err = json.Unmarshal(data, &counters)
	if err != nil {
		t.Error(err)
	}

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

func TestDump701(t *testing.T) {
	data, err := os.ReadFile("./testdata/dump-counters-7.0.1.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]any
	err = json.Unmarshal(data, &counters)
	if err != nil {
		t.Error(err)
	}

	metrics := produceMetricsHelper(counters)
	agged := aggregateMetrics(metrics)

	tms := agged["suricata_flow_mgr_flows_checked_total"]

	if len(tms) != 2 {
		t.Errorf("Unexpected number of suricata_flow_mgr_flows_checked_total: %v", len(tms))
	}
}

func TestDump706NFQAutoFP(t *testing.T) {
	data, err := os.ReadFile("./testdata/dump-counters-7.0.6-nfq-autofp.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]any
	err = json.Unmarshal(data, &counters)
	if err != nil {
		t.Error(err)
	}

	metrics := produceMetricsHelper(counters)
	agged := aggregateMetrics(metrics)

	tms := agged["suricata_ips_blocked_packets_total"]
	if len(tms) != 14 {
		t.Errorf("Unexpected number of suricata_ips_blocked_total: %v", len(tms))
	}

	threadNames := sortedThreadNames(tms)
	if threadNames != "[RX-NFQ#0 RX-NFQ#1 RX-NFQ#2 RX-NFQ#3 TX#00 TX#01 TX#02 TX#03 W#01 W#02 W#03 W#04 W#05 W#06]" {
		t.Errorf("Wrong threads %v", threadNames)
	}
}

func TestDump706NFQWorkers(t *testing.T) {
	data, err := os.ReadFile("./testdata/dump-counters-7.0.6-nfq-workers.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]any
	err = json.Unmarshal(data, &counters)
	if err != nil {
		t.Error(err)
	}

	metrics := produceMetricsHelper(counters)
	agged := aggregateMetrics(metrics)

	tms := agged["suricata_ips_blocked_packets_total"]
	if len(tms) != 4 {
		t.Errorf("Unexpected number of suricata_ips_blocked_total: %v", len(tms))
	}

	threadNames := sortedThreadNames(tms)
	if threadNames != "[W-NFQ#0 W-NFQ#1 W-NFQ#2 W-NFQ#3]" {
		t.Errorf("Wrong threads %v", threadNames)
	}
}

func TestDump706AFPacketAutoFP(t *testing.T) {
	data, err := os.ReadFile("./testdata/dump-counters-7.0.6-afpacket-autofp.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]any
	err = json.Unmarshal(data, &counters)
	if err != nil {
		t.Error(err)
	}

	metrics := produceMetricsHelper(counters)
	agged := aggregateMetrics(metrics)
	tms, ok := agged["suricata_capture_kernel_packets_total"] // test metrics
	if !ok {
		t.Errorf("Failed to find suricata_capture_kernel_packets metrics")
	}

	if len(tms) != 2 {
		t.Errorf("Unexpected number of suricata_kernel_packets metrics: %v", len(tms))
	}

	threadNames := sortedThreadNames(tms)
	if threadNames != "[RX#01 RX#02]" {
		t.Errorf("Wrong threads %v", threadNames)
	}

	tms, ok = agged["suricata_decoder_packets_total"]
	if !ok {
		t.Errorf("Failed to find suricata_decoder_packets_total metrics")
	}

	// Decoder stats are reported for rx and worker threads.
	if len(tms) != 8 {
		t.Errorf("Unexpected number of suricata_decoder_packets_total metrics: %v", len(tms))
	}

	tms, ok = agged["suricata_tcp_syn_packets_total"]
	if !ok {
		t.Errorf("Failed to find suricata_tcp_syn_packets_total")
	}

	// TCP metrics report for rx and worker threads.
	if len(tms) != 8 {
		t.Errorf("Unexpected number of suricata_decoder_packets_total metrics: %v", len(tms))
	}
}
