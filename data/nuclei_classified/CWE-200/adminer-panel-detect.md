# Vulnerability: Adminer Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`adminer-panel-detect.yaml`)

## Description
Adminer login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{path}} HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Referer: {{BaseURL}}
```

