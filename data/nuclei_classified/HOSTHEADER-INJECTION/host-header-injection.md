# Vulnerability: Host Header Injection
**Classification:** HOSTHEADER-INJECTION
**Source:** Nuclei Template (`host-header-injection.yaml`)

## Description
HTTP header injection is a general class of web application security vulnerability which occurs when Hypertext Transfer Protocol headers are dynamically generated based on user input.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

