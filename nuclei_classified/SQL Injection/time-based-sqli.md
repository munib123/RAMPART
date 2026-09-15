# Nuclei Template: Time-Based Blind SQL Injection
**Template ID:** time-based-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**Source:** Nuclei Template (`time-based-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Sends time-delay SQL payloads and measures response latency to confirm blind injection in various database engines, enabling data extraction without direct error messages.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
@timeout: 20s
GET / HTTP/1.1
Host: {{Hostname}}
```

