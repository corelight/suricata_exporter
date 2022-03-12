# Suricata Prometheus Exporter

This is a Prometheus Exporter for Suricata using `dump-counters` via the
[unix socket](https://suricata.readthedocs.io/en/suricata-6.0.0/unix-socket.html#interacting-via-unix-socket)
to query metrics.


## Usage

```
$ ./suricata_exporter -h
Usage of ./suricata_exporter:
  -suricata.socket-path string
        Path to the Suricata Command socket. (default "/var/run/suricata.socket")
  -version
        Output version information.
  -web.listen-address string
        Address to listen on (default ":9916")
```

To verify the exporter is working with your Suricata setup, use the
following command to view a subset of the capture metrics.

```
$ curl -s localhost:9916/metrics | grep kernel_packets_total
# HELP suricata_capture_kernel_packets_total
# TYPE suricata_capture_kernel_packets_total counter
suricata_capture_kernel_packets_total{thread="W#01-eth1"} 7744
suricata_capture_kernel_packets_total{thread="W#02-eth1"} 8435
suricata_capture_kernel_packets_total{thread="W#03-eth1"} 7564
suricata_capture_kernel_packets_total{thread="W#04-eth1"} 9747
```

You can now configure a [Prometheus server](https://prometheus.io/docs/prometheus/latest/getting_started/)
to scrape the Suricata exporter in regular intervals for later visualization
and analysis.


## Metrics

Currently produces per-thread metrics for `decoder`, `flow`, `flow_bypassed`,
`app_layer` and `tcp`. Metrics for `memuse` are reported globally.

## Compatibility

Developed against Suricata 6.0.4 and af-packet. Most supported metrics are
hard-coded.
