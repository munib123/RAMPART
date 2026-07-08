# Vulnerability: Epson Printer
**Classification:** CWE-200
**Source:** Nuclei Template (`epson-web-control-detect.yaml`)

## Description
An Epson printer web panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/home
```

