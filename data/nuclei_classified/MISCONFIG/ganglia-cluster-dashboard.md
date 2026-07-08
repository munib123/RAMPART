# Vulnerability: Ganglia Cluster Dashboard - Detect
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ganglia-cluster-dashboard.yaml`)

## Description
Ganglia Cluster dashboard was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/ganglia/
```

