# Vulnerability: Cluster Overview Trino - Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`cluster-trino-panel.yaml`)

## Description
Cluster Overview Trino Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/login.html
```

