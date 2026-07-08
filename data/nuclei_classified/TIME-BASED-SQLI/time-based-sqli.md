# Vulnerability: Time-Based Blind SQL Injection
**Classification:** TIME-BASED-SQLI
**Source:** Nuclei Template (`time-based-sqli.yaml`)

## Description
Sends time-delay SQL payloads and measures response latency to confirm blind injection in various database engines, enabling data extraction without direct error messages.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
@timeout: 20s
GET / HTTP/1.1
Host: {{Hostname}}
```

