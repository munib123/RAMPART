# Vulnerability: Prometheus Promtail - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`prometheus-promtail.yaml`)

## Description
Prometheus Promtail is an agent that gathers log data from various sources, such as files or systemd journal.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/service-discovery
```

