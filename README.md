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
        Address to listen on (default ":9867")
```

## Metrics

Currently produces per-thread metrics for `decoder`, `flow`, `flow_bypassed`,
`app_layer` and `tcp`. Metrics for `memuse` are reported globally.

## Compatibility

Developed against Suricata 6.0.4 and af-packet. Most supported metrics are
hard-coded.
