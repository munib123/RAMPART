# Vulnerability: Sendmail .forward File - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`sendmail-forward-exposure.yaml`)

## Description
Sendmail .forward file is publicly accessible. This file is used to configure email forwarding and can expose sensitive information including email addresses, forwarding rules, and potentially executable commands (pipe to programs).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.forward
```

