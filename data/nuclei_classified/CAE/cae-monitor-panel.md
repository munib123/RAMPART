# Vulnerability: CAE Monitoring - Login Panel
**Classification:** CAE
**Source:** Nuclei Template (`cae-monitor-panel.yaml`)

## Description
Identified an exposed CAE Monitoring login panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.html
```

