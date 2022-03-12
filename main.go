// Copyright 2021 Corelight, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metricInfo struct {
	desc     *prometheus.Desc
	t        prometheus.ValueType
	field    string
	optional bool
}

// Mark the given metricInfo as optional
func (m metricInfo) Optional() metricInfo {
	m.optional = true
	return m
}

func newMetric(subsystem, name, docString string, t prometheus.ValueType, field string, variableLabels []string) metricInfo {
	return metricInfo{
		desc: prometheus.NewDesc(
			prometheus.BuildFQName("suricata", subsystem, name),
			docString,
			variableLabels,
			nil,
		),
		t:     t,
		field: field,
	}

}

func newCounterMetric(subsystem, name, docString string, field string, variableLabels ...string) metricInfo {
	return newMetric(subsystem, name, docString, prometheus.CounterValue, field, variableLabels)
}
func newGaugeMetric(subsystem, name, docString string, field string, variableLabels ...string) metricInfo {
	return newMetric(subsystem, name, docString, prometheus.GaugeValue, field, variableLabels)
}

func newPerThreadCounterMetric(subsystem, name, docString string, field string, variableLabels ...string) metricInfo {
	return newCounterMetric(subsystem, name, docString, field, append(variableLabels, "thread")...)
}

func newPerThreadGaugeMetric(subsystem, name, docString string, field string, variableLabels ...string) metricInfo {
	return newGaugeMetric(subsystem, name, docString, field, append(variableLabels, "thread")...)
}

// All the metrics we pull out from dump-counters.
//
// Hmm, hmm, might be able to auto-generate/unify this a bit. But harder if
// we actually start documenting individual fields.
var (
	metricUptime = newMetric("", "uptime_seconds", "Uptime for the Suricata process in seconds", prometheus.GaugeValue, "uptime", []string{})

	// From .thread.tcp
	perThreadCaptureMetrics = []metricInfo{
		newPerThreadCounterMetric("capture", "kernel_packets_total", "", "kernel_packets"),
		newPerThreadCounterMetric("capture", "kernel_drops_total", "", "kernel_drops"),
		newPerThreadCounterMetric("capture", "errors_total", "", "errors").Optional(),
	}

	// Not quite sure it would be better to have those as labels or separate
	// metrics. But summing them up seems weird (think tcp on top of ipv4 inside gre),
	// so keeping them as separate metrics for now.
	//
	// From: .thread.decoder
	perThreadDecoderMetrics = []metricInfo{
		newPerThreadCounterMetric("decoder", "packets_total", "", "pkts"),
		newPerThreadCounterMetric("decoder", "bytes_total", "", "bytes"),
		newPerThreadCounterMetric("decoder", "invalid_packets_total", "", "invalid"),
		newPerThreadCounterMetric("decoder", "ipv4_packets_total", "", "ipv4"),
		newPerThreadCounterMetric("decoder", "ipv6_packets_total", "", "ipv6"),
		newPerThreadCounterMetric("decoder", "ethernet_packets_total", "", "ethernet"),
		newPerThreadCounterMetric("decoder", "chdlc_packets_total", "", "chdlc"),
		newPerThreadCounterMetric("decoder", "raw_packets_total", "", "raw"),
		newPerThreadCounterMetric("decoder", "null_packets_total", "", "null"),
		newPerThreadCounterMetric("decoder", "sll_packets_total", "", "sll"),
		newPerThreadCounterMetric("decoder", "tcp_packets_total", "", "tcp"),
		newPerThreadCounterMetric("decoder", "udp_packets_total", "", "udp"),
		newPerThreadCounterMetric("decoder", "sctp_packets_total", "", "sctp"),
		newPerThreadCounterMetric("decoder", "icmpv4_packets_total", "", "icmpv4"),
		newPerThreadCounterMetric("decoder", "icmpv6_packets_total", "", "icmpv6"),
		newPerThreadCounterMetric("decoder", "ppp_packets_total", "", "ppp"),
		newPerThreadCounterMetric("decoder", "pppoe_packets_total", "", "pppoe"),
		newPerThreadCounterMetric("decoder", "geneve_packets_total", "", "geneve"),
		newPerThreadCounterMetric("decoder", "gre_packets_total", "", "gre"),
		newPerThreadCounterMetric("decoder", "vlan_packets_total", "", "vlan"),
		newPerThreadCounterMetric("decoder", "vlan_qinq_packets_total", "", "vlan_qinq"),
		newPerThreadCounterMetric("decoder", "vxlan_packets_total", "", "vxlan"),
		newPerThreadCounterMetric("decoder", "vntag_packets_total", "", "vntag"),
		newPerThreadCounterMetric("decoder", "ieee8021ah_packets_total", "", "ieee8021ah"),
		newPerThreadCounterMetric("decoder", "teredo_packets_total", "", "teredo"),
		newPerThreadCounterMetric("decoder", "ipv4_in_ipv6_packets_total", "", "ipv4_in_ipv6"),
		newPerThreadCounterMetric("decoder", "ipv6_in_ipv6_packets_total", "", "ipv6_in_ipv6"),
		newPerThreadCounterMetric("decoder", "mpls_packets_total", "", "mpls"),

		// They are there, so include them.
		newPerThreadGaugeMetric("decoder", "packet_size_avg", "", "avg_pkt_size"),
		newPerThreadGaugeMetric("decoder", "packet_size_max", "", "max_pkt_size"),

		newPerThreadCounterMetric("decoder", "too_many_layers_total", "", "too_many_layers"),
	}

	// From .thread.flow
	perThreadFlowMetrics = []metricInfo{
		newPerThreadCounterMetric("flow", "tcp_total", "", "tcp"),
		newPerThreadCounterMetric("flow", "udp_total", "", "udp"),
		newPerThreadCounterMetric("flow", "icmpv4_total", "", "icmpv4"),
		newPerThreadCounterMetric("flow", "icmpv6_total", "", "icmpv6"),
		newPerThreadCounterMetric("flow", "tcp_reuse_total", "", "tcp_reuse"),
	}

	// From .thread.flow.wrk
	perThreadFlowWrkMetrics = []metricInfo{
		newPerThreadGaugeMetric("flow_wrk", "spare_sync_avg", "", "spare_sync_avg"),
		newPerThreadCounterMetric("flow_wrk", "spare_sync_total", "", "spare_sync"),
		newPerThreadCounterMetric("flow_wrk", "spare_sync_incomplete_total", "", "spare_sync_incomplete"),
		newPerThreadCounterMetric("flow_wrk", "spare_sync_empty_total", "", "spare_sync_empty"),
		newPerThreadCounterMetric("flow_wrk", "flows_evicted_needs_work_total", "", "flows_evicted_needs_work"),
		newPerThreadCounterMetric("flow_wrk", "flows_evicted_pkt_inject_total", "", "flows_evicted_pkt_inject"),
		newPerThreadCounterMetric("flow_wrk", "flows_evicted_total", "", "flows_evicted"),
		newPerThreadCounterMetric("flow_wrk", "flows_injected_total", "", "flows_injected"),
		newPerThreadCounterMetric("flow_wrk", "flows_evicted_needs_work", "", "flows_evicted_needs_work"),
	}

	// From .thread.defrag
	perThreadDefragIpv4Metrics = []metricInfo{
		newPerThreadCounterMetric("defrag", "ipv4_fragments_total", "", "fragments"),
		newPerThreadCounterMetric("defrag", "ipv4_reassembled_total", "", "reassembled"),
		newPerThreadCounterMetric("defrag", "ipv4_timeouts_total", "", "timeouts"),
	}

	perThreadDefragIpv6Metrics = []metricInfo{
		newPerThreadCounterMetric("defrag", "ipv6_fragments_total", "", "fragments"),
		newPerThreadCounterMetric("defrag", "ipv6_reassembled_total", "", "reassembled"),
		newPerThreadCounterMetric("defrag", "ipv6_timeouts_total", "", "timeouts"),
	}
	perThreadDefragMetrics = []metricInfo{
		newPerThreadGaugeMetric("defrag", "max_frag_hits", "", "max_frag_hits"),
	}

	// From .thread.flow_bypassed
	perThreadFlowBypassedMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_bypassed", "local_packets_total", "", "local_pkts"),
		newPerThreadCounterMetric("flow_bypassed", "local_bytes_total", "", "local_bytes"),
		newPerThreadCounterMetric("flow_bypassed", "local_capture_packets_total", "", "local_capture_pkts"),
		newPerThreadCounterMetric("flow_bypassed", "local_capture_bytes_total", "", "local_capture_bytes"),
	}

	// From .thread.tcp
	perThreadTcpMetrics = []metricInfo{
		newPerThreadCounterMetric("tcp", "sessions_total", "", "sessions"),
		newPerThreadCounterMetric("tcp", "ssn_memcap_drop_total", "", "ssn_memcap_drop"),
		newPerThreadCounterMetric("tcp", "pseudo_total", "", "pseudo"),
		newPerThreadCounterMetric("tcp", "pseudo_failed_total", "", "pseudo"),
		newPerThreadCounterMetric("tcp", "invalid_checksum_packets_total", "", "invalid_checksum"),
		newPerThreadCounterMetric("tcp", "no_flow_total", "", "no_flow"),
		newPerThreadCounterMetric("tcp", "syn_packets_total", "", "syn"),
		newPerThreadCounterMetric("tcp", "synack_packets_total", "", "synack"),
		newPerThreadCounterMetric("tcp", "rst_packets_total", "", "rst"),
		newPerThreadCounterMetric("tcp", "midstream_pickups_total", "", "midstream_pickups"),
		newPerThreadCounterMetric("tcp", "pkt_on_wrong_thread_total", "", "pkt_on_wrong_thread"),
		newPerThreadCounterMetric("tcp", "segment_memcap_drop_total", "", "segment_memcap_drop"),
		newPerThreadCounterMetric("tcp", "stream_depth_reached_total", "", "stream_depth_reached"),
		newPerThreadCounterMetric("tcp", "reassembly_gap_total", "", "reassembly_gap"),
		newPerThreadCounterMetric("tcp", "overlap_total", "", "overlap"),
		newPerThreadCounterMetric("tcp", "overlap_diff_data_total", "", "overlap_diff_data"),
		newPerThreadCounterMetric("tcp", "insert_data_normal_fail_total", "", "insert_data_normal_fail"),
		newPerThreadCounterMetric("tcp", "insert_data_overlap_fail_total", "", "insert_data_overlap_fail"),
		newPerThreadCounterMetric("tcp", "insert_list_fail_total", "", "insert_list_fail"),
	}

	// From .thread.detect
	perThreadDetectMetrics = []metricInfo{
		newPerThreadCounterMetric("detect", "alerts_total", "", "alert"),
	}

	// From: .thread.app_layer, labeled with the key. I think summing
	// those up is more reasonable than the decoder keys to get a total
	// count of app-layer detections.
	perThreadAppLayerFlowMetric = newPerThreadCounterMetric("app_layer", "flows_total", "", "<unused>", "app")

	// Flow manager

	// From .thread.flow.mgr
	perThreadFlowMgrMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_mgr", "full_hash_pass_total", "", "full_hash_pass"),
		newPerThreadCounterMetric("flow_mgr", "closed_pruned_total", "", "closed_pruned"),
		newPerThreadCounterMetric("flow_mgr", "new_pruned_total", "", "new_pruned"),
		newPerThreadCounterMetric("flow_mgr", "est_pruned_total", "", "est_pruned"),
		newPerThreadCounterMetric("flow_mgr", "bypassed_pruned_total", "", "bypassed_pruned"),
		newPerThreadGaugeMetric("flow_mgr", "rows_maxlen", "", "rows_maxlen"),
		newPerThreadCounterMetric("flow_mgr", "flows_checked_total", "", "flows_checked"),
		newPerThreadCounterMetric("flow_mgr", "flows_notimeout_total", "", "flows_notimeout"),
		newPerThreadCounterMetric("flow_mgr", "flow_timeout_total", "", "flows_timeout"),
		newPerThreadCounterMetric("flow_mgr", "flow_timeout_inuse", "", "flows_timeout_inuse"),
		newPerThreadCounterMetric("flow_mgr", "flows_evicted_total", "", "flows_evicted"),
		newPerThreadGaugeMetric("flow_mgr", "flows_evicted_needs_work", "", "flows_evicted_needs_work"),
	}

	// From .thread.flow_bypassed (for flow manager threads)
	perThreadFlowMgrBypassedMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_bypassed", "closed_total", "", "closed"),
		newPerThreadCounterMetric("flow_bypassed", "packets_total", "", "pkts"),
		newPerThreadCounterMetric("flow_bypassed", "bytes_total", "", "bytes"),
	}

	// From .message.tcp
	globalTcpMetrics = []metricInfo{
		newGaugeMetric("tcp", "memuse_bytes", "", "memuse"),
		newGaugeMetric("tcp", "reassembly_memuse_bytes", "", "reassembly_memuse"),
	}

	// From .message.flow - these should be shared across FMs
	globalFlowMetrics = []metricInfo{
		newGaugeMetric("flow", "spare", "", "spare"),
		newCounterMetric("flow", "emerg_mode_entered_total", "", "emerg_mode_entered"),
		newCounterMetric("flow", "emerg_mode_over_total", "", "emerg_mode_over"),
		newGaugeMetric("flow", "memuse_bytes", "", "memuse"),
	}

	// From .message.{http,ftp}
	httpMemuseMetric = newGaugeMetric("http", "memuse_bytes", "", "<unused>")
	ftpMemuseMetric  = newGaugeMetric("ftp", "memuse_bytes", "", "<unused>")

	// detect.engines[]
	rulesLoadedMetric = newGaugeMetric("detect_engine", "rules_loaded", "", "<unused>", "id")
	rulesFailedMetric = newGaugeMetric("detect_engine", "rules_failed", "", "<unused>", "id")
	lastReloadMetric  = newGaugeMetric("detect_engine", "last_reload_timestamp_seconds", "Last reload as Unix timestamp", "<unused>", "id")
)

// Send a version message and dump-counters command over the
// Suricata unix socket and return the dump-counters response
// as map[string]interface{}
//
// May want to cleanup/generalize if there's ever a reason to support
// more commands.
func dumpCounters(conn net.Conn) (map[string]interface{}, error) {
	var parsed map[string]interface{}
	var line []byte
	var err error
	var cmdData []byte

	// Send the version as hand-shake.
	cmdData, _ = json.Marshal(map[string]string{
		"version": "0.2",
	})
	fmt.Fprintf(conn, "%s\n", string(cmdData))

	reader := bufio.NewReader(conn)
	line, err = reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(line, &parsed)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse version response from Suricata: %v", err)
	}

	if parsed["return"] != "OK" {
		return nil, fmt.Errorf("No OK response from Suricata: %v", parsed)
	}

	// Send dump-counters command.
	cmdData, _ = json.Marshal(map[string]string{
		"command": "dump-counters",
	})
	fmt.Fprintf(conn, "%s\n", string(cmdData))

	// Read until '\n' shows up or there was an error. A lot of data
	// is retuned, so may read short.
	var response []byte
	for {
		data, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}

		response = append(response, data...)
		if data[len(data)-1] == '\n' {
			break
		}
	}

	parsed = make(map[string]interface{})
	if err := json.Unmarshal(response, &parsed); err != nil {
		return nil, err
	}
	if parsed["return"] != "OK" {
		return nil, fmt.Errorf("ERROR: No OK response from Suricata: %v", parsed)
	}

	return parsed, nil
}

// Produce a new for the metricInfo
func newConstMetric(m metricInfo, data map[string]interface{}, labelValues ...string) prometheus.Metric {

	field_value, ok := data[m.field]
	if !ok {
		if !m.optional {
			log.Printf("ERROR: Field %s missing for %v", m.field, m.desc)
		}
		return nil
	}

	value, ok := field_value.(float64)
	if !ok {
		log.Printf("ERROR: Field %s missing for %v", m.field, m.desc)
		return nil
	}

	// fmt.Printf("m.desc=%v m.field=%v\n", m.desc, m.field)
	return prometheus.MustNewConstMetric(m.desc, m.t, value, labelValues...)
}

type suricataCollector struct {
	socketPath string
}

func (sc *suricataCollector) Describe(ch chan<- *prometheus.Desc) {
	// No need?
}

func handleWorkerThread(ch chan<- prometheus.Metric, threadName string, thread map[string]interface{}) {
	if capture, ok := thread["capture"].(map[string]interface{}); ok {
		for _, m := range perThreadCaptureMetrics {
			if cm := newConstMetric(m, capture, threadName); cm != nil {
				ch <- cm
			}
		}
	}

	tcp := thread["tcp"].(map[string]interface{})
	for _, m := range perThreadTcpMetrics {
		if cm := newConstMetric(m, tcp, threadName); cm != nil {
			ch <- cm
		}
	}

	flow := thread["flow"].(map[string]interface{})
	for _, m := range perThreadFlowMetrics {
		if cm := newConstMetric(m, flow, threadName); cm != nil {
			ch <- cm
		}
	}

	wrk := flow["wrk"].(map[string]interface{})
	for _, m := range perThreadFlowWrkMetrics {
		if cm := newConstMetric(m, wrk, threadName); cm != nil {
			ch <- cm
		}
	}

	defrag := thread["defrag"].(map[string]interface{})
	defragIpv4 := defrag["ipv4"].(map[string]interface{})
	defragIpv6 := defrag["ipv6"].(map[string]interface{})
	for _, m := range perThreadDefragIpv4Metrics {
		if cm := newConstMetric(m, defragIpv4, threadName); cm != nil {
			ch <- cm
		}
	}
	for _, m := range perThreadDefragIpv6Metrics {
		if cm := newConstMetric(m, defragIpv6, threadName); cm != nil {
			ch <- cm
		}
	}
	for _, m := range perThreadDefragMetrics {
		if cm := newConstMetric(m, defrag, threadName); cm != nil {
			ch <- cm
		}
	}

	detect := thread["detect"].(map[string]interface{})
	for _, m := range perThreadDetectMetrics {
		if cm := newConstMetric(m, detect, threadName); cm != nil {
			ch <- cm
		}
	}

	// Convert all decoder entries that look like numbers
	// as perThreadDecoder metric with a "kind" label.
	decoder := thread["decoder"].(map[string]interface{})
	for _, m := range perThreadDecoderMetrics {
		if cm := newConstMetric(m, decoder, threadName); cm != nil {
			ch <- cm
		}
	}

	bypassed := thread["flow_bypassed"].(map[string]interface{})
	for _, m := range perThreadFlowBypassedMetrics {
		if cm := newConstMetric(m, bypassed, threadName); cm != nil {
			ch <- cm
		}
	}

	// Convert all app_layer entries that look like numbers
	// as metrics with a "proto" label.
	//
	// suricata_app_layer_flows_total{app="ntp",thread="W#08-wlp0s20f3"} 87
	// suricata_app_layer_flows_total{app="tls",thread="W#04-wlp0s20f3"} 204
	appLayer := thread["app_layer"].(map[string]interface{})
	appLayerFlow := appLayer["flow"].(map[string]interface{})
	for k, v := range appLayerFlow {
		value, ok := v.(float64)
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(perThreadAppLayerFlowMetric.desc,
			perThreadAppLayerFlowMetric.t, value, k, threadName)

	}
}

func handleFlowManagerThread(ch chan<- prometheus.Metric, threadName string, thread map[string]interface{}) {
	flow := thread["flow"].(map[string]interface{})
	mgr := flow["mgr"].(map[string]interface{})
	for _, m := range perThreadFlowMgrMetrics {
		if cm := newConstMetric(m, mgr, threadName); cm != nil {
			ch <- cm
		}
	}

	flowBypassed := thread["flow_bypassed"].(map[string]interface{})
	for _, m := range perThreadFlowMgrBypassedMetrics {
		if cm := newConstMetric(m, flowBypassed, threadName); cm != nil {
			ch <- cm
		}
	}
}

// Handle global metrics.
func handleGlobal(ch chan<- prometheus.Metric, message map[string]interface{}) {
	if globalTcp, ok := message["tcp"].(map[string]interface{}); ok {
		for _, m := range globalTcpMetrics {
			if cm := newConstMetric(m, globalTcp); cm != nil {
				ch <- cm
			}
		}
	} else {
		log.Printf("WARN: No top-level tcp entry in message")
	}

	if globalFlow, ok := message["flow"].(map[string]interface{}); ok {
		for _, m := range globalFlowMetrics {
			if cm := newConstMetric(m, globalFlow); cm != nil {
				ch <- cm
			}
		}
	} else {
		log.Printf("WARN: No top-level flow entry message")
	}

	if globalHttp, ok := message["http"].(map[string]interface{}); ok {
		ch <- prometheus.MustNewConstMetric(httpMemuseMetric.desc,
			httpMemuseMetric.t, globalHttp["memuse"].(float64))
	} else {
		log.Printf("WARN: No top-level http entry message")
	}

	if globalFtp, ok := message["ftp"].(map[string]interface{}); ok {
		ch <- prometheus.MustNewConstMetric(ftpMemuseMetric.desc,
			httpMemuseMetric.t, globalFtp["memuse"].(float64))
	} else {
		log.Printf("WARN: No top-level ftp entry message")
	}

	if globalDetect, ok := message["detect"].(map[string]interface{}); ok {
		if engines, ok := globalDetect["engines"].([]interface{}); ok {
			for _, e := range engines {
				em := e.(map[string]interface{})
				engine_id := strconv.Itoa(int(em["id"].(float64)))
				rules_loaded := em["rules_loaded"].(float64)
				rules_failed := em["rules_failed"].(float64)
				ch <- prometheus.MustNewConstMetric(rulesLoadedMetric.desc,
					rulesLoadedMetric.t, rules_loaded, engine_id)
				ch <- prometheus.MustNewConstMetric(rulesFailedMetric.desc,
					rulesLoadedMetric.t, rules_failed, engine_id)

				last_reload := em["last_reload"].(string)
				layout := "2006-01-02T15:04:05.999999-0700"

				if t, err := time.Parse(layout, last_reload); err == nil {
					ch <- prometheus.MustNewConstMetric(lastReloadMetric.desc,
						lastReloadMetric.t, float64(t.Unix()), engine_id)
				} else {
					log.Printf("WARN: Could not parse last_reload %q: %v", last_reload, err)
				}
			}
		} else {
			log.Printf("WARN: No detect.engines entry")
		}

	} else {
		log.Printf("WARN: No top-level detect entry")
	}

}

func produceMetrics(ch chan<- prometheus.Metric, counters map[string]interface{}) {

	message := counters["message"].(map[string]interface{})

	// Uptime metric
	ch <- newConstMetric(metricUptime, message)

	// Produce per thread metrics
	for threadName, thread_ := range message["threads"].(map[string]interface{}) {
		thread := thread_.(map[string]interface{})

		if strings.HasPrefix(threadName, "W#") {
			handleWorkerThread(ch, threadName, thread)
		} else if strings.HasPrefix(threadName, "FM") {
			handleFlowManagerThread(ch, threadName, thread)
		} else if threadName == "Global" {
			// Skip
		} else {
			log.Printf("WARN: Unhandled thread: %s", threadName)
		}
	}

	handleGlobal(ch, message)

}

func (sc *suricataCollector) Collect(ch chan<- prometheus.Metric) {
	conn, err := net.Dial("unix", sc.socketPath)
	if err != nil {
		log.Printf("ERROR: Failed to connect to %v: %v", sc.socketPath, err)
		return
	}
	defer conn.Close()

	counters, err := dumpCounters(conn)
	if err != nil {
		log.Printf("ERROR: Failed to dump-counters: %v", err)
		return
	}

	produceMetrics(ch, counters)
}

var (
	version     string // Set via -ldflags -X main.version=...
	showVersion = flag.Bool("version", false, "Output version information.")
	socketPath  = flag.String("suricata.socket-path", "/var/run/suricata.socket", "Path to the Suricata Command socket.")
	addr        = flag.String("web.listen-address", ":9916", "Address to listen on")
)

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("%s\n", version)
		return
	}
	r := prometheus.NewRegistry()
	r.MustRegister(&suricataCollector{*socketPath})
	http.ListenAndServe(*addr, promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
}
