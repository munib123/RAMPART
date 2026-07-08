# Vulnerability: Laragon - phpinfo Disclosure
**Classification:** LARAGON
**Source:** Nuclei Template (`laragon-phpinfo.yaml`)

## Description
Laragon phpinfo file was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?q=info
```

