// Expose Suricata dump-counter metrics via Prometheus.
//
// Copyright (c) 2022, Corelight, Inc. All rights reserved.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
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

	// From .thread.capture
	perThreadCaptureMetrics = []metricInfo{
		newPerThreadCounterMetric("capture", "kernel_packets_total", "", "kernel_packets"),
		newPerThreadCounterMetric("capture", "kernel_drops_total", "", "kernel_drops"),
		newPerThreadCounterMetric("capture", "errors_total", "", "errors").Optional(),
	}

	// .thread.capture.afpacket
	perThreadCaptureAFPacketMetrics = []metricInfo{
		newPerThreadGaugeMetric("capture", "afpacket_busy_loop_avg", "", "busy_loop_avg"),
		// The following 4 are put into a single metrics afpacket_polls_total
		// where the result is a labels.
		// newPerThreadCounterMetric("capture", "afpacket_poll_total", "", "polls"),
		// newPerThreadCounterMetric("capture", "afpacket_poll_signal_total", "", "poll_signal"),
		// newPerThreadCounterMetric("capture", "afpacket_poll_timeout_total", "", "poll_timeout"),
		// newPerThreadCounterMetric("capture", "afpacket_poll_data_total", "", "poll_data"),
		// newPerThreadCounterMetric("capture", "afpacket_poll_errors_total", "", "poll_errors"),
		newPerThreadCounterMetric("capture", "afpacket_send_errors_total", "", "send_errors"),
	}

	// Collect individual afpacket_poll outcomes into a single metric.
	perThreadAFPacketPollResultMetric = newPerThreadCounterMetric("capture", "afpacket_poll_results_total", "", "<unused>", "result")

	// Entries in afpacket to the label
	perThreadAFPacketPollResultEntries = [][2]string{
		{"poll_signal", "signal"},
		{"poll_timeout", "timeout"},
		{"poll_data", "data"},
		{"poll_errors", "error"},
	}

	// Not quite sure if it would be better to have those as labels or separate
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
		// New in 7.0.0
		newPerThreadCounterMetric("decoder", "arp_packets_total", "", "arp").Optional(),
		newPerThreadCounterMetric("decoder", "unknown_ethertype_packets_total", "", "unknown_ethertype").Optional(),
		newPerThreadCounterMetric("decoder", "chdlc_packets_total", "", "chdlc"),
		newPerThreadCounterMetric("decoder", "raw_packets_total", "", "raw"),
		newPerThreadCounterMetric("decoder", "null_packets_total", "", "null"),
		newPerThreadCounterMetric("decoder", "sll_packets_total", "", "sll"),
		newPerThreadCounterMetric("decoder", "tcp_packets_total", "", "tcp"),
		newPerThreadCounterMetric("decoder", "udp_packets_total", "", "udp"),
		newPerThreadCounterMetric("decoder", "sctp_packets_total", "", "sctp"),
		// New in 7.0.0
		newPerThreadCounterMetric("decoder", "esp_packets_total", "", "esp").Optional(),
		newPerThreadCounterMetric("decoder", "icmpv4_packets_total", "", "icmpv4"),
		newPerThreadCounterMetric("decoder", "icmpv6_packets_total", "", "icmpv6"),
		newPerThreadCounterMetric("decoder", "ppp_packets_total", "", "ppp"),
		newPerThreadCounterMetric("decoder", "pppoe_packets_total", "", "pppoe"),
		newPerThreadCounterMetric("decoder", "geneve_packets_total", "", "geneve"),
		newPerThreadCounterMetric("decoder", "gre_packets_total", "", "gre"),
		newPerThreadCounterMetric("decoder", "vlan_packets_total", "", "vlan"),
		newPerThreadCounterMetric("decoder", "vlan_qinq_packets_total", "", "vlan_qinq"),
		// New in 7.0.0
		newPerThreadCounterMetric("decoder", "vlan_qinqinq_packets_total", "", "vlan_qinqinq").Optional(),
		newPerThreadCounterMetric("decoder", "vxlan_packets_total", "", "vxlan"),
		newPerThreadCounterMetric("decoder", "vntag_packets_total", "", "vntag"),
		newPerThreadCounterMetric("decoder", "ieee8021ah_packets_total", "", "ieee8021ah"),
		newPerThreadCounterMetric("decoder", "teredo_packets_total", "", "teredo"),
		newPerThreadCounterMetric("decoder", "ipv4_in_ipv6_packets_total", "", "ipv4_in_ipv6"),
		newPerThreadCounterMetric("decoder", "ipv6_in_ipv6_packets_total", "", "ipv6_in_ipv6"),
		newPerThreadCounterMetric("decoder", "mpls_packets_total", "", "mpls"),
		newPerThreadCounterMetric("decoder", "erspan_packets_total", "", "erspan"),
		// New in 7.0.0
		newPerThreadCounterMetric("decoder", "nsh_packets_total", "", "nsh").Optional(),

		// They are there, so include them.
		newPerThreadGaugeMetric("decoder", "packet_size_avg", "", "avg_pkt_size"),
		newPerThreadGaugeMetric("decoder", "packet_size_max", "", "max_pkt_size"),
		newPerThreadGaugeMetric("decoder", "mac_address_src_max", "", "max_mac_addrs_src"),
		newPerThreadGaugeMetric("decoder", "mac_address_dst_max", "", "max_mac_addrs_dst"),

		newPerThreadCounterMetric("decoder", "too_many_layers_total", "", "too_many_layers"),
	}

	// From: .thread.decoder.event.afpacket
	// New in 8.0.0: d78f2c9a4e2b59f44daeddff098915084493d08d
	perThreadDecoderEventAFPacketMetrics = []metricInfo{
		newPerThreadCounterMetric("decoder_event", "afpacket_truncated_packets_total", "", "trunc_pkt"),
	}

	// From .thread.flow
	perThreadFlowMetrics = []metricInfo{
		// New in 7.0.0: b0993d6fd8ffb6abafdea9324cd0166106af1851
		newPerThreadCounterMetric("flow", "all_total", "", "total").Optional(),
		newPerThreadGaugeMetric("flow", "active_flows", "", "active").Optional(),
		newPerThreadCounterMetric("flow", "tcp_total", "", "tcp"),
		newPerThreadCounterMetric("flow", "udp_total", "", "udp"),
		// New in 8.0.0: 0aea82677644a7e9476059a8be4d29953e4ab712
		newPerThreadCounterMetric("flow", "elephant_total", "", "elephant").Optional(),
		newPerThreadCounterMetric("flow", "icmpv4_total", "", "icmpv4"),
		newPerThreadCounterMetric("flow", "icmpv6_total", "", "icmpv6"),
		newPerThreadCounterMetric("flow", "tcp_reuse_total", "", "tcp_reuse"),
		newPerThreadCounterMetric("flow", "get_used_total", "", "get_used").Optional(),
		newPerThreadCounterMetric("flow", "get_used_eval_total", "", "get_used_eval").Optional(),
		newPerThreadCounterMetric("flow", "get_used_eval_reject_total", "", "get_used_eval_reject").Optional(),
		newPerThreadCounterMetric("flow", "get_used_eval_busy_total", "", "get_used_eval_busy").Optional(),
		newPerThreadCounterMetric("flow", "get_used_failed_total", "", "get_used_failed_total").Optional(),
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
		newPerThreadGaugeMetric("flow_wrk", "flows_injected_max", "", "flows_injected_max").Optional(),
	}

	// From .thread.flow.end
	perThreadFlowEndMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_end", "tcp_liberal_total", "", "tcp_liberal").Optional(),
	}

	// From .thread.flow.end.state
	// New in 7.0.0: b0993d6fd8ffb6abafdea9324cd0166106af1851
	perThreadFlowEndStateMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_end_state", "new_total", "", "new").Optional(),
		newPerThreadCounterMetric("flow_end_state", "established_total", "", "established").Optional(),
		newPerThreadCounterMetric("flow_end_state", "closed_total", "", "closed").Optional(),
		newPerThreadCounterMetric("flow_end_state", "local_bypassed_total", "", "local_bypassed").Optional(),
		newPerThreadCounterMetric("flow_end_state", "capture_bypassed_total", "", "capture_bypassed").Optional(),
	}

	// From .thread.flow.end.tcp_state
	// New in 7.0.0: b0993d6fd8ffb6abafdea9324cd0166106af1851
	perThreadFlowEndTcpStateMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_end_tcpstate", "syn_sent_total", "", "syn_sent").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "syn_recv_total", "", "syn_recv").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "established_total", "", "established").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "fin_wait1_total", "", "fin_wait1").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "fin_wait2_total", "", "fin_wait2").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "time_wait_total", "", "time_wait").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "last_ack_total", "", "last_ack").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "close_wait_total", "", "close_wait").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "closing_total", "", "closing").Optional(),
		newPerThreadCounterMetric("flow_end_tcpstate", "closed_total", "", "closed").Optional(),
	}

	// From .thread.defrag
	perThreadDefragIpv4Metrics = []metricInfo{
		newPerThreadCounterMetric("defrag", "ipv4_fragments_total", "", "fragments"),
		newPerThreadCounterMetric("defrag", "ipv4_reassembled_total", "", "reassembled"),
		// Removed in 7.0.0: a37a88dcd5950344fc0b4529f1731c3dab9f0888
		newPerThreadCounterMetric("defrag", "ipv4_timeouts_total", "", "timeouts").Optional(),
	}

	perThreadDefragIpv6Metrics = []metricInfo{
		newPerThreadCounterMetric("defrag", "ipv6_fragments_total", "", "fragments"),
		newPerThreadCounterMetric("defrag", "ipv6_reassembled_total", "", "reassembled"),
		// Removed in 7.0.0: a37a88dcd5950344fc0b4529f1731c3dab9f0888
		newPerThreadCounterMetric("defrag", "ipv6_timeouts_total", "", "timeouts").Optional(),
	}
	perThreadDefragMetrics = []metricInfo{
		// Removed in 8.0.0: 83dc703d1fd5a435178f220a3e79cd65b73b4cbb
		newPerThreadGaugeMetric("defrag", "max_frag_hits", "", "max_frag_hits").Optional(),
		// New in 8.0.0: 83dc703d1fd5a435178f220a3e79cd65b73b4cbb
		newPerThreadGaugeMetric("defrag", "max_trackers_reached", "", "max_trackers_reached").Optional(),
		newPerThreadGaugeMetric("defrag", "max_fragments_reached", "", "max_frags_reached").Optional(),
		newPerThreadCounterMetric("defrag", "tracker_soft_reuse_total", "", "tracker_soft_reuse").Optional(),
		newPerThreadCounterMetric("defrag", "tracker_hard_reuse_total", "", "tracker_hard_reuse").Optional(),
	}

	// From .thread.flow_bypassed
	perThreadFlowBypassedMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_bypassed", "local_packets_total", "", "local_pkts"),
		newPerThreadCounterMetric("flow_bypassed", "local_bytes_total", "", "local_bytes"),
		newPerThreadCounterMetric("flow_bypassed", "local_capture_packets_total", "", "local_capture_pkts"),
		newPerThreadCounterMetric("flow_bypassed", "local_capture_bytes_total", "", "local_capture_bytes"),
	}

	perThreadIpsMetrics = []metricInfo{
		newPerThreadCounterMetric("ips", "accepted_packets_total", "", "accepted"),
		newPerThreadCounterMetric("ips", "blocked_packets_total", "", "blocked"),
		newPerThreadCounterMetric("ips", "rejected_packets_total", "", "rejected"),
		newPerThreadCounterMetric("ips", "replaced_packets_total", "", "replaced"),
	}

	perThreadTcpMetricsReceive = []metricInfo{
		newPerThreadCounterMetric("tcp", "syn_packets_total", "", "syn"),
		newPerThreadCounterMetric("tcp", "synack_packets_total", "", "synack"),
		newPerThreadCounterMetric("tcp", "rst_packets_total", "", "rst"),
		// New in 8.0.0: 6882bcb3e51bd3cf509fb6569cc30f48d7bb53d7
		newPerThreadCounterMetric("tcp", "urg_packets_total", "", "urg").Optional(),
	}

	// From .thread.tcp
	perThreadTcpMetrics = []metricInfo{
		// New in 7.0.0
		newPerThreadCounterMetric("tcp", "ack_unseen_data_total", "", "ack_unseen_data").Optional(),
		// Not sure if active is working on a per-thread basis: Seems to be a counter going
		// up on the worker threads and down on the flow recycler. Seems a bit borked :-/
		// newPerThreadGaugeMetric("tcp", "sessions_active", "", "active_sessions").Optional(),
		newPerThreadCounterMetric("tcp", "segment_from_cache_total", "", "segment_from_cache").Optional(),
		newPerThreadCounterMetric("tcp", "segment_from_pool_total", "", "segment_from_pool").Optional(),
		newPerThreadCounterMetric("tcp", "ssn_from_cache_total", "", "ssn_from_cache").Optional(),
		newPerThreadCounterMetric("tcp", "ssn_from_pool_total", "", "ssn_from_pool").Optional(),

		newPerThreadCounterMetric("tcp", "sessions_total", "", "sessions"),
		newPerThreadCounterMetric("tcp", "ssn_memcap_drop_total", "", "ssn_memcap_drop"),
		newPerThreadCounterMetric("tcp", "pseudo_total", "", "pseudo"),
		// Removed in 8.0.0 b967fcaf8f6fee4ddbe9f3276fcb7e5e8139b993
		newPerThreadCounterMetric("tcp", "pseudo_failed_total", "", "pseudo_failed").Optional(),
		newPerThreadCounterMetric("tcp", "invalid_checksum_packets_total", "", "invalid_checksum"),
		// Removed in 7.0.0: 0360cb654293c333e3be70204705fa7ec328512e
		newPerThreadCounterMetric("tcp", "no_flow_total", "", "no_flow").Optional(),
		newPerThreadCounterMetric("tcp", "midstream_pickups_total", "", "midstream_pickups"),
		newPerThreadCounterMetric("tcp", "pkt_on_wrong_thread_total", "", "pkt_on_wrong_thread"),
		newPerThreadCounterMetric("tcp", "segment_memcap_drop_total", "", "segment_memcap_drop"),
		newPerThreadCounterMetric("tcp", "stream_depth_reached_total", "", "stream_depth_reached"),
		newPerThreadCounterMetric("tcp", "reassembly_gap_total", "", "reassembly_gap"),
		newPerThreadCounterMetric("tcp", "overlap_total", "", "overlap"),
		newPerThreadCounterMetric("tcp", "overlap_diff_data_total", "", "overlap_diff_data"),
		newPerThreadCounterMetric("tcp", "insert_data_normal_fail_total", "", "insert_data_normal_fail"),
		newPerThreadCounterMetric("tcp", "insert_data_overlap_fail_total", "", "insert_data_overlap_fail"),
		// Removed in 7.0.0: f34845858ccc011d4dfffcf111d1b779ba133763
		newPerThreadCounterMetric("tcp", "insert_list_fail_total", "", "insert_list_fail").Optional(),
		// New in 8.0.0: 6882bcb3e51bd3cf509fb6569cc30f48d7bb53d7
		newPerThreadCounterMetric("tcp", "urgent_oob_data_total", "", "urgent_oob_data").Optional(),
	}

	// From .thread.detect
	perThreadDetectMetrics = []metricInfo{
		newPerThreadCounterMetric("detect", "alerts_total", "", "alert"),
		// New in 7.0.0
		newPerThreadCounterMetric("detect", "alert_queue_overflows_total", "", "alert_queue_overflow").Optional(),
		newPerThreadCounterMetric("detect", "alerts_suppressed_total", "", "alerts_suppressed").Optional(),
	}

	// From .thread.file_store
	perThreadFileStoreMetrics = []metricInfo{
		newPerThreadGaugeMetric("filestore", "open_files_max_hit", "", "open_files_max_hit").Optional(),
		newPerThreadCounterMetric("filestore", "fs_errors_total", "", "fs_errors").Optional(),
	}

	// From: .thread.app_layer, labeled with the key. I think summing
	// those up is more reasonable than the decoder keys to get a total
	// count of app-layer detections.
	perThreadAppLayerFlowMetric = newPerThreadCounterMetric("app_layer", "flows_total", "", "<unused>", "app")

	// Flow manager

	// From .thread.flow.mgr
	perThreadFlowMgrMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_mgr", "full_hash_pass_total", "", "full_hash_pass"),
		// Removed in 7.0.0: b0ce55c9df285ebeddd58ff35dd3f3ef15589671
		newPerThreadCounterMetric("flow_mgr", "closed_pruned_total", "", "closed_pruned").Optional(),
		newPerThreadCounterMetric("flow_mgr", "new_pruned_total", "", "new_pruned").Optional(),
		newPerThreadCounterMetric("flow_mgr", "est_pruned_total", "", "est_pruned").Optional(),
		newPerThreadCounterMetric("flow_mgr", "bypassed_pruned_total", "", "bypassed_pruned").Optional(),
		// Add in 7.0.0: 88edc8630c6dd3ff659d23cc7e21f361bec0ce72
		newPerThreadGaugeMetric("flow_mgr", "rows_per_sec", "", "rows_per_sec").Optional(),
		newPerThreadGaugeMetric("flow_mgr", "rows_maxlen", "", "rows_maxlen"),
		newPerThreadCounterMetric("flow_mgr", "flows_checked_total", "", "flows_checked"),
		newPerThreadCounterMetric("flow_mgr", "flows_notimeout_total", "", "flows_notimeout"),
		newPerThreadCounterMetric("flow_mgr", "flow_timeout_total", "", "flows_timeout"),
		// Removed in 7.0.0: 66ed3ae6e4d047fa156572dea0216b0d4f3308ad
		newPerThreadCounterMetric("flow_mgr", "flow_timeout_inuse", "", "flows_timeout_inuse").Optional(),
		newPerThreadCounterMetric("flow_mgr", "flows_evicted_total", "", "flows_evicted"),
		newPerThreadGaugeMetric("flow_mgr", "flows_evicted_needs_work", "", "flows_evicted_needs_work"),
	}

	// From .thread.flow_bypassed (for flow manager threads)
	perThreadFlowMgrBypassedMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_bypassed", "closed_total", "", "closed"),
		newPerThreadCounterMetric("flow_bypassed", "packets_total", "", "pkts"),
		newPerThreadCounterMetric("flow_bypassed", "bytes_total", "", "bytes"),
	}
	// From .thread.flow.recycler
	perThreadFlowRecyclerMetrics = []metricInfo{
		newPerThreadCounterMetric("flow_recycler", "recycled_total", "", "recycled"),
		newPerThreadGaugeMetric("flow_recycler", "queue_avg", "", "queue_avg"),
		newPerThreadGaugeMetric("flow_recycler", "queue_max", "", "queue_max"),
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

	// From .message.defrag
	// Add in 8.0.0: 83dc703d1fd5a435178f220a3e79cd65b73b4cbb
	globalDefragMetrics = []metricInfo{
		newGaugeMetric("defrag", "memuse_bytes", "", "memuse").Optional(),
	}

	// From .message.{http,ftp}
	httpMemuseMetric = newGaugeMetric("http", "memuse_bytes", "", "<unused>")
	ftpMemuseMetric  = newGaugeMetric("ftp", "memuse_bytes", "", "<unused>")

	// detect.engines[]
	rulesLoadedMetric = newGaugeMetric("detect_engine", "rules_loaded", "", "<unused>", "id")
	rulesFailedMetric = newGaugeMetric("detect_engine", "rules_failed", "", "<unused>", "id")
	lastReloadMetric  = newGaugeMetric("detect_engine", "last_reload_timestamp_seconds", "Last reload as Unix timestamp", "<unused>", "id")

	// Napatech
	napaTotalMetrics = []metricInfo{
		newCounterMetric("napatech", "packets_total", "", "pkts"),
		newCounterMetric("napatech", "bytes_total", "", "byte"),
		newCounterMetric("napatech", "overflow_drop_packets_total", "", "overflow_drop_pkts"),
		newCounterMetric("napatech", "overflow_drop_bytes_total", "", "overflow_drop_byte"),
	}
	napaDispatchHost = []metricInfo{
		newCounterMetric("napatech", "dispatch_host_packets_total", "", "pkts"),
		newCounterMetric("napatech", "dispatch_host_bytes_total", "", "byte"),
	}
	napaDispatchDrop = []metricInfo{
		newCounterMetric("napatech", "dispatch_drop_packets_total", "", "pkts"),
		newCounterMetric("napatech", "dispatch_drop_bytes_total", "", "byte"),
	}

	// Metric desc used for reporting collection failures
	FailedCollectionDesc = prometheus.NewDesc(
		prometheus.BuildFQName("suricata", "collection", "failure"),
		"invalid metric for reporting collection failures",
		[]string{},
		nil,
	)

	SuricataUp = prometheus.NewDesc(
		"suricata_up",
		"Indicates if the Suricata service is reachable by the exporter (1 = reachable, 0 = unreachable)",
		nil,
		nil,
	)

	SuricataVersionInfo = prometheus.NewDesc(
		"suricata_version_info",
		"Suricata version information",
		[]string{"version"},
		nil,
	)

	// Errors used for above metric
	errConnect      = errors.New("failed to connect")
	errDumpCounters = errors.New("failed to dump-counters")
)

func NewSuricataClient(socketPath string) *SuricataClient {
	return &SuricataClient{socketPath: socketPath}
}

type SuricataClient struct {
	socketPath string
	conn       net.Conn
}

func (c *SuricataClient) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}

	c.conn = nil
}

func (c *SuricataClient) EnsureConnection() error {
	var rerr error

	for range 2 {
		if c.conn == nil {
			// Try to establish UNIX connection and do the
			// handshake. Either of these failing is fatal.
			conn, err := net.Dial("unix", c.socketPath)
			if err != nil {
				return err
			}

			c.conn = conn
			if err := c.Handshake(); err != nil {
				return err
			}
		}

		// If we get here, we had a connection or we have a new one,
		// see if it's still valid by invoking uptime.
		if _, err := c.Uptime(); err != nil {
			log.Printf("ERROR: uptime command failed: %v", err)
			rerr = err
			continue
		}

		// Uptime worked, we're done.
		return nil

	}

	return rerr
}

// Do the version handshake. Returns nil or the error.
func (c *SuricataClient) Handshake() error {
	// Send the version as hand-shake.
	cmdData, err := json.Marshal(map[string]string{
		"version": "0.2",
	})
	if err != nil {
		c.Close()
		return err
	}

	_, err = fmt.Fprintf(c.conn, "%s\n", string(cmdData))
	if err != nil {
		return fmt.Errorf("failed to write to Suricata: %w", err)
	}

	reader := bufio.NewReader(c.conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		c.Close()
		return fmt.Errorf("failed read response from Suricata: %w", err)
	}

	var parsed map[string]any
	err = json.Unmarshal(line, &parsed)
	if err != nil {
		c.Close()
		return fmt.Errorf("failed to parse version response from Suricata: %w", err)
	}

	if parsed["return"] != "OK" {
		c.Close()
		return fmt.Errorf("no \"OK\" response from Suricata: %v", parsed)
	}

	return nil
}

func (c *SuricataClient) Uptime() (uint64, error) {
	cmdData, err := json.Marshal(map[string]string{
		"command": "uptime",
	})
	if err != nil {
		c.Close()
		return 0, err
	}

	_, err = fmt.Fprintf(c.conn, "%s\n", string(cmdData))
	if err != nil {
		return 0, fmt.Errorf("failed to write to Suricata: %w", err)
	}

	reader := bufio.NewReader(c.conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		c.Close()
		return 0, fmt.Errorf("failed read response from Suricata: %w", err)
	}

	var parsed map[string]any
	err = json.Unmarshal(line, &parsed)
	if err != nil {
		c.Close()
		return 0, fmt.Errorf("failed to parse version response from Suricata: %w", err)
	}

	if parsed["return"] != "OK" {
		c.Close()
		return 0, fmt.Errorf("no \"OK\" response from Suricata: %v", parsed)
	}

	uptime, ok := parsed["message"].(float64)

	if !ok {
		return 0, fmt.Errorf("could get uptime from response: %v", parsed)
	}

	return uint64(uptime), nil
}

// Send dump-counters command and return JSON as parsed map[string]any
func (c *SuricataClient) DumpCounters() (map[string]any, error) {
	cmdData, err := json.Marshal(map[string]string{
		"command": "dump-counters",
	})
	if err != nil {
		c.Close()
		return nil, err
	}

	_, err = fmt.Fprintf(c.conn, "%s\n", string(cmdData))
	if err != nil {
		return nil, fmt.Errorf("failed to write to Suricata: %w", err)
	}

	// Read until '\n' shows up or there was an error. A lot of data
	// is returned, so may read short.
	reader := bufio.NewReader(c.conn)
	var response []byte
	for {
		data, err := reader.ReadBytes('\n')
		if err != nil {
			c.Close()
			return nil, err
		}

		response = append(response, data...)
		if data[len(data)-1] == '\n' {
			break
		}
	}

	var parsed map[string]any
	if err := json.Unmarshal(response, &parsed); err != nil {
		c.Close()
		return nil, err
	}
	if parsed["return"] != "OK" {
		c.Close()
		return nil, fmt.Errorf("ERROR: No OK response from Suricata: %v", parsed)
	}

	return parsed, nil
}

// Produce a new for the metricInfo
func newConstMetric(m metricInfo, data map[string]any, labelValues ...string) prometheus.Metric {

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

// Extract Napatech related metrics from message
func handleNapatechMetrics(ch chan<- prometheus.Metric, message map[string]any) {
	if napaTotal, ok := message["napa_total"].(map[string]any); ok {
		for _, m := range napaTotalMetrics {
			if cm := newConstMetric(m, napaTotal); cm != nil {
				ch <- cm
			}
		}
	}
	if napaTotal, ok := message["napa_dispatch_host"].(map[string]any); ok {
		for _, m := range napaDispatchHost {
			if cm := newConstMetric(m, napaTotal); cm != nil {
				ch <- cm
			}
		}
	}
	if napaTotal, ok := message["napa_dispatch_drop"].(map[string]any); ok {
		for _, m := range napaDispatchDrop {
			if cm := newConstMetric(m, napaTotal); cm != nil {
				ch <- cm
			}
		}
	}
}

// Handle the shared RX and worker thread portions.
//
// Depending on autofp or workers runmode, the "capture" entry
// is in the RX threads.
func handleReceiveCommon(ch chan<- prometheus.Metric, threadName string, thread map[string]any) {
	if capture, ok := thread["capture"].(map[string]any); ok {
		for _, m := range perThreadCaptureMetrics {
			if cm := newConstMetric(m, capture, threadName); cm != nil {
				ch <- cm
			}
		}

		if afpacket, ok := capture["afpacket"].(map[string]any); ok {
			for _, m := range perThreadCaptureAFPacketMetrics {
				if cm := newConstMetric(m, afpacket, threadName); cm != nil {
					ch <- cm
				}
			}

			for _, key_label := range perThreadAFPacketPollResultEntries {
				k := key_label[0]
				label := key_label[1]

				if value, ok := afpacket[k].(float64); ok {
					ch <- prometheus.MustNewConstMetric(
						perThreadAFPacketPollResultMetric.desc,
						perThreadAFPacketPollResultMetric.t,
						value, label, threadName)
				} else {
					log.Printf("ERROR: Failed afpacket %v in %v", k, afpacket)
				}
			}
		}
	}

	// Convert all decoder entries that look like numbers
	// as perThreadDecoder metric with a "kind" label.
	decoder, decoder_status := thread["decoder"].(map[string]any);
	if decoder_status {
		for _, m := range perThreadDecoderMetrics {
			if cm := newConstMetric(m, decoder, threadName); cm != nil {
				ch <- cm
			}
		}

		event, event_status := decoder["event"].(map[string]any);
		if event_status {
			if event_afpacket, ok := event["afpacket"].(map[string]any); ok {
				for _, m := range perThreadDecoderEventAFPacketMetrics {
					if cm := newConstMetric(m, event_afpacket, threadName); cm != nil {
						ch <- cm
					}
				}
			}
		}
	}

	// Handle decoder events

	// Defrag stats from worker and receive threads.
	defrag, defrag_status := thread["defrag"].(map[string]any)
	if defrag_status {
		defragIpv4, defragIpv4_status := defrag["ipv4"].(map[string]any)
		if defragIpv4_status {
			for _, m := range perThreadDefragIpv4Metrics {
				if cm := newConstMetric(m, defragIpv4, threadName); cm != nil {
					ch <- cm
				}
			}
		}
		defragIpv6, defragIpv6_status := defrag["ipv6"].(map[string]any)
		if defragIpv6_status {
			for _, m := range perThreadDefragIpv6Metrics {
				if cm := newConstMetric(m, defragIpv6, threadName); cm != nil {
					ch <- cm
				}
			}
		}
		for _, m := range perThreadDefragMetrics {
			if cm := newConstMetric(m, defrag, threadName); cm != nil {
				ch <- cm
			}
		}
  }


	tcp, tcp_status := thread["tcp"].(map[string]any)
	if tcp_status {
		for _, m := range perThreadTcpMetricsReceive {
			if cm := newConstMetric(m, tcp, threadName); cm != nil {
				ch <- cm
			}
		}
	}
}

func handleIps(ch chan<- prometheus.Metric, threadName string, thread map[string]any) {
	// Extract basic IPS metrics if they exist.
	if ips, ok := thread["ips"].(map[string]any); ok {
		for _, m := range perThreadIpsMetrics {
			if cm := newConstMetric(m, ips, threadName); cm != nil {
				ch <- cm
			}
		}
	}
}

// Receive threads have the same layout as worker threads.
func handleReceiveThread(ch chan<- prometheus.Metric, threadName string, thread map[string]any) {
	handleReceiveCommon(ch, threadName, thread)
	handleIps(ch, threadName, thread)
}

func handleTransmitThread(ch chan<- prometheus.Metric, threadName string, thread map[string]any) {
	handleIps(ch, threadName, thread)
}

func handleFlowEndCommon(ch chan<- prometheus.Metric, threadName string, flow map[string]any) {
	// Handle flow end metrics in common between WK and FR threads.

	if end, ok := flow["end"].(map[string]any); ok {
		for _, m := range perThreadFlowEndMetrics {
			if cm := newConstMetric(m, end, threadName); cm != nil {
				ch <- cm
			}
		}

		if state, ok := end["state"].(map[string]any); ok {
			for _, m := range perThreadFlowEndStateMetrics {
				if cm := newConstMetric(m, state, threadName); cm != nil {
					ch <- cm
				}
			}
		}

		if tcp_state, ok := end["tcp_state"].(map[string]any); ok {
			for _, m := range perThreadFlowEndTcpStateMetrics {
				if cm := newConstMetric(m, tcp_state, threadName); cm != nil {
					ch <- cm
				}
			}
		}
	}
}

func handleWorkerThread(ch chan<- prometheus.Metric, threadName string, thread map[string]any) {
	handleReceiveCommon(ch, threadName, thread)
	handleIps(ch, threadName, thread)

	tcp := thread["tcp"].(map[string]any)
	for _, m := range perThreadTcpMetrics {
		if cm := newConstMetric(m, tcp, threadName); cm != nil {
			ch <- cm
		}
	}

	flow := thread["flow"].(map[string]any)
	for _, m := range perThreadFlowMetrics {
		if cm := newConstMetric(m, flow, threadName); cm != nil {
			ch <- cm
		}
	}

	wrk := flow["wrk"].(map[string]any)
	for _, m := range perThreadFlowWrkMetrics {
		if cm := newConstMetric(m, wrk, threadName); cm != nil {
			ch <- cm
		}
	}

	// Handle flow end metrics
	handleFlowEndCommon(ch, threadName, flow)

	detect := thread["detect"].(map[string]any)
	for _, m := range perThreadDetectMetrics {
		if cm := newConstMetric(m, detect, threadName); cm != nil {
			ch <- cm
		}
	}

	// If enabled in Suricata configuration
	if file_store, ok := thread["file_store"].(map[string]any); ok {
		for _, m := range perThreadFileStoreMetrics {
			if cm := newConstMetric(m, file_store, threadName); cm != nil {
				ch <- cm
			}
		}
	}

	bypassed := thread["flow_bypassed"].(map[string]any)
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
	appLayer := thread["app_layer"].(map[string]any)
	appLayerFlow := appLayer["flow"].(map[string]any)
	for k, v := range appLayerFlow {
		value, ok := v.(float64)
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(perThreadAppLayerFlowMetric.desc,
			perThreadAppLayerFlowMetric.t, value, k, threadName)

	}
}

func handleFlowManagerThread(ch chan<- prometheus.Metric, threadName string, thread map[string]any) {
	flow := thread["flow"].(map[string]any)
	mgr := flow["mgr"].(map[string]any)
	for _, m := range perThreadFlowMgrMetrics {
		if cm := newConstMetric(m, mgr, threadName); cm != nil {
			ch <- cm
		}
	}

	flowBypassed := thread["flow_bypassed"].(map[string]any)
	for _, m := range perThreadFlowMgrBypassedMetrics {
		if cm := newConstMetric(m, flowBypassed, threadName); cm != nil {
			ch <- cm
		}
	}
}

// Handle flow recycler metrics
func handleFlowRecyclerThread(ch chan<- prometheus.Metric, threadName string, thread map[string]any) {
	flow := thread["flow"].(map[string]any)
	recycler := flow["recycler"].(map[string]any)
	for _, m := range perThreadFlowRecyclerMetrics {
		if cm := newConstMetric(m, recycler, threadName); cm != nil {
			ch <- cm
		}
	}

	if threadName != "Total" {
		// Handle flow end metrics
		handleFlowEndCommon(ch, threadName, flow)
	}
}

// Handle global metrics.
func handleGlobal(ch chan<- prometheus.Metric, message map[string]any) {
	if globalTcp, ok := message["tcp"].(map[string]any); ok {
		for _, m := range globalTcpMetrics {
			if cm := newConstMetric(m, globalTcp); cm != nil {
				ch <- cm
			}
		}
	} else {
		log.Printf("WARN: No top-level tcp entry in message")
	}

	if globalFlow, ok := message["flow"].(map[string]any); ok {
		for _, m := range globalFlowMetrics {
			if cm := newConstMetric(m, globalFlow); cm != nil {
				ch <- cm
			}
		}
	} else {
		log.Printf("WARN: No top-level flow entry message")
	}

	if globalDefrag, ok := message["defrag"].(map[string]any); ok {
		for _, m := range globalDefragMetrics {
			if cm := newConstMetric(m, globalDefrag); cm != nil {
				ch <- cm
			}
		}
	} else {
		log.Printf("WARN: No top-level defrag entry message")
	}

	if globalHttp, ok := message["http"].(map[string]any); ok {
		ch <- prometheus.MustNewConstMetric(httpMemuseMetric.desc,
			httpMemuseMetric.t, globalHttp["memuse"].(float64))
	} else {
		log.Printf("WARN: No top-level http entry message")
	}

	if globalFtp, ok := message["ftp"].(map[string]any); ok {
		ch <- prometheus.MustNewConstMetric(ftpMemuseMetric.desc,
			httpMemuseMetric.t, globalFtp["memuse"].(float64))
	} else {
		log.Printf("WARN: No top-level ftp entry message")
	}

	if globalDetect, ok := message["detect"].(map[string]any); ok {
		if engines, ok := globalDetect["engines"].([]any); ok {
			for _, e := range engines {
				em := e.(map[string]any)
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

	if *totals {
		// Export the overall global metrics calculated as the sum of all threads.
		// The entries defined at the top-level have the same structure of the thread ones
		handleWorkerThread(ch, "Total", message)
		handleFlowManagerThread(ch, "Total", message)
		handleFlowRecyclerThread(ch, "Total", message)
	}

}

func produceMetrics(ch chan<- prometheus.Metric, counters map[string]any) {

	message := counters["message"].(map[string]any)

	// Uptime metric
	ch <- newConstMetric(metricUptime, message)

	// Version info metric (string value exposed as a label)
	if version, ok := message["version"].(string); ok {
		ch <- prometheus.MustNewConstMetric(SuricataVersionInfo, prometheus.GaugeValue, 1, version)
	}

	// Produce per thread metrics if not in totals mode.
	if !*totals {
		for threadName, thread_ := range message["threads"].(map[string]any) {
			if thread, ok := thread_.(map[string]any); ok {
				if strings.HasPrefix(threadName, "W#") || strings.HasPrefix(threadName, "W-") {
					handleWorkerThread(ch, threadName, thread)
				} else if strings.HasPrefix(threadName, "RX") {
					handleReceiveThread(ch, threadName, thread)
				} else if strings.HasPrefix(threadName, "TX") {
					handleTransmitThread(ch, threadName, thread)
				} else if strings.HasPrefix(threadName, "FM") {
					handleFlowManagerThread(ch, threadName, thread)
				} else if strings.HasPrefix(threadName, "FR") {
					handleFlowRecyclerThread(ch, threadName, thread)
				} else if threadName == "Global" {
					// Skip
				} else if threadName == "NapatechStats" {
					// Skip
				} else {
					log.Printf("WARN: Unhandled thread: %s", threadName)
				}
			} else {
				// The following two show up under threads in 7.0.x,
				// ignore them.
				//
				// https://redmine.openinfosecfoundation.org/issues/6398
				if threadName != "memcap_pressure" && threadName != "memcap_pressure_max" {
					log.Printf("WARN: Threads entry %s not a map[string]", threadName)
				}
			}
		}
	}

	handleGlobal(ch, message)

	// Global Napatech metrics if available
	handleNapatechMetrics(ch, message)
}

type suricataCollector struct {
	client *SuricataClient
	mu     sync.Mutex // SuricataClient is not re-entrant, easy way out.
}

func (sc *suricataCollector) Describe(ch chan<- *prometheus.Desc) {
	// No need?
}

func (sc *suricataCollector) Collect(ch chan<- prometheus.Metric) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if err := sc.client.EnsureConnection(); err != nil {
		if !*quiet {
			log.Printf("ERROR: Failed to connect to %v", err)
		}

		ch <- prometheus.NewInvalidMetric(FailedCollectionDesc, errConnect)
		return
	}

	ch <- prometheus.MustNewConstMetric(SuricataUp, prometheus.GaugeValue, 1)

	counters, err := sc.client.DumpCounters()
	if err != nil {
		log.Printf("ERROR: Failed to dump-counters: %v", err)
		ch <- prometheus.NewInvalidMetric(FailedCollectionDesc, errDumpCounters)
		return
	}

	produceMetrics(ch, counters)
}

var (
	version     string // Set via -ldflags -X main.version=...
	showVersion = flag.Bool("version", false, "Output version information.")
	socketPath  = flag.String("suricata.socket-path", "/var/run/suricata.socket", "Path to the Suricata Command socket.")
	addr        = flag.String("web.listen-address", ":9917", "Address to listen on")
	path        = flag.String("web.telemetry-path", "/metrics", "Path for metrics")
	quiet       = flag.Bool("quiet", false, "Suppress log output")
	totals      = flag.Bool("totals", false, "Export the overall global total metrics.")
)

func main() {
	flag.Parse()

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Unexpected positional arguments: %q\n", flag.Args())
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("%s\n", version)
		return
	}

	r := prometheus.NewRegistry()
	r.MustRegister(&suricataCollector{NewSuricataClient(*socketPath), sync.Mutex{}})

	http.Handle(*path, promhttp.HandlerFor(r, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
	}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`<html>
			<head><title>Suricata Exporter</title></head>
			<body>
			<h1>Suricata Exporter</h1>
			<p><a href="` + *path + `">Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	})

	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatalf("Error listenAndServe: %v", err)
	}
}
