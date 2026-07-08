# Vulnerability: Prometheus Config API Endpoint Discovery
**Classification:** PROMETHEUS
**Source:** Nuclei Template (`prometheus-config.yaml`)

## Description
A Prometheus config API endpoint was discovered. The config endpoint returns the loaded Prometheus configuration file along with the addresses of targets and alerting/discovery services alongside the credentials required to access them. Usually, Prometheus replaces the passwords in the credentials config configuration field with the placeholder <secret> (although this still leaks the username).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/status/config
```

