# Vulnerability: Citrix Honeypot - Detect
**Classification:** CITRIX
**Source:** Nuclei Template (`citrix-honeypot-detect.yaml`)

## Description
A Citrix honeypot has been identified.
The HTTP response reveals a possible setup of the Citrix web application honeypot.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

