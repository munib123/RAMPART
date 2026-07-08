# Vulnerability: Blackbox Exporter - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`blackbox-exporter-exposure.yaml`)

## Description
Blackbox Exporter was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

