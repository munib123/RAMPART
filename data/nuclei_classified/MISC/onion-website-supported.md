# Vulnerability: Onion Website Supported via Onion-Location Header
**Classification:** MISC
**Source:** Nuclei Template (`onion-website-supported.yaml`)

## Description
Identified websites that supported Tor network access through the Onion-Location HTTP response header, which pointed to a corresponding .onion service for enhanced privacy and anonymity.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

