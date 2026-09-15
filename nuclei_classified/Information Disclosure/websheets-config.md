# Nuclei Template: Websheets Configuration File - Detect
**Template ID:** websheets-config
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`websheets-config.yaml`)

## Vulnerability Information & PoC

## Description
Websheets configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ws-config.json
GET {{BaseURL}}/ws-config.example.json
```

## References
- https://github.com/daveagp/websheets
