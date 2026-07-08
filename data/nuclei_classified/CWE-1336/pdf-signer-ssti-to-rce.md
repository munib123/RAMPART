# Vulnerability: PDF Signer 3.0 - Template Injection
**Classification:** CWE-1336
**Source:** Nuclei Template (`pdf-signer-ssti-to-rce.yaml`)

## Description
PDF Signer 3.0 is susceptible to a template injection which allows code execution, due to improper cookie handling and an improper CSRF implementation. An attacker can execute code on the server in the context of the web server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

