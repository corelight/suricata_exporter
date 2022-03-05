package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var sample_counters = map[string]interface{}{
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

func TestProduceMetricsRules(t *testing.T) {

	ch := make(chan prometheus.Metric)
	finished := make(chan bool)

	go func() {
		produceMetrics(ch, sample_counters)
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

	ch := make(chan prometheus.Metric)
	finished := make(chan bool)

	go func() {
		produceMetrics(ch, sample_counters)
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

	ch := make(chan prometheus.Metric)
	finished := make(chan bool)

	go func() {
		produceMetrics(ch, counters)
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

	// This is a bit dumb because once more metrics are added this isn't
	// useful, but testing individual metrics is a bit annoying.
	if len(metrics) != 890 {
		t.Errorf("Expected 889 metrics, got %d", len(metrics))
	}
}

func TestDump604Netmap(t *testing.T) {
	data, err := ioutil.ReadFile("./testdata/dump-counters-6.0.4-netmap.json")
	if err != nil {
		log.Panicf("Unable to open file: %s", err)
	}

	var counters map[string]interface{}
	json.Unmarshal(data, &counters)

	ch := make(chan prometheus.Metric)
	finished := make(chan bool)

	go func() {
		produceMetrics(ch, counters)
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

	// This is a bit dumb because once more metrics are added this isn't
	// useful, but testing individual metrics is a bit annoying.
	if len(metrics) != 231 {
		t.Errorf("Expected 231 metrics, got %d", len(metrics))
	}
}
