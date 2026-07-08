# Vulnerability: KubeView Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kubeview-dashboard.yaml`)

## Description
KubeView dashboard was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

