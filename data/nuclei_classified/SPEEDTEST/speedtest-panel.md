# Vulnerability: Speedtest Panel - Detection
**Classification:** SPEEDTEST
**Source:** Nuclei Template (`speedtest-panel.yaml`)

## Description
Speedtest panel was discovered

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

