# Vulnerability: Dozzle - Logs Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`dozzle-container-logs.yaml`)

## Description
Dozzle is a small lightweight application with a web based interface to monitor Docker logs. It doesn’t store any log files. It is for live monitoring of your container logs only.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

