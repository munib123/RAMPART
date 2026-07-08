# Vulnerability: InfluxDB Admin Interface Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`influxdb-panel.yaml`)

## Description
InfluxDB admin interface panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

