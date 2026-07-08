# Vulnerability: Barracuda Message Archiver - Panel Detect
**Classification:** BARRACUDA
**Source:** Nuclei Template (`barracuda-message-panel.yaml`)

## Description
Barracuda Networks Barracuda Message Archiver (BMA) panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-mod/index.cgi
```

