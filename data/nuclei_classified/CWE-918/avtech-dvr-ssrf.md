# Vulnerability: AVTECH DVR - SSRF
**Classification:** CWE-918
**Source:** Nuclei Template (`avtech-dvr-ssrf.yaml`)

## Description
AVTECH DVR device, Search.cgi can be accessed directly. Search.cgi is responsible for searching and accessing cameras in the local network. Search.cgi provides the cgi_query function.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/nobody/Search.cgi?action=scan
```

