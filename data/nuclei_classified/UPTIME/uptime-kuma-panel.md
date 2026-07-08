# Vulnerability: Uptime Kuma - Panel
**Classification:** UPTIME
**Source:** Nuclei Template (`uptime-kuma-panel.yaml`)

## Description
Realtime website and application monitoring tool

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard
```

