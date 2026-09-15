# Nuclei Template: AVTECH DVR - SSRF
**Template ID:** avtech-dvr-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Medium
**CWE:** CWE-918
**Source:** Nuclei Template (`avtech-dvr-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
AVTECH DVR device, Search.cgi can be accessed directly. Search.cgi is responsible for searching and accessing cameras in the local network. Search.cgi provides the cgi_query function.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/nobody/Search.cgi?action=scan
```

