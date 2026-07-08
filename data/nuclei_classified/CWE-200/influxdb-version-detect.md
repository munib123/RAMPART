# Vulnerability: InfluxDB Version Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`influxdb-version-detect.yaml`)

## Description
InfluxDB version information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

