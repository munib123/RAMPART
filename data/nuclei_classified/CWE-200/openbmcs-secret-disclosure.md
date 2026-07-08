# Vulnerability: OpenBMCS 2.4 - Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`openbmcs-secret-disclosure.yaml`)

## Description
OpenBMCS 2.4 contains an information disclosure vulnerability. The application allows directory listing and exposure of some sensitive files, which can allow an attacker to leverage the disclosed information and gain full access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/debug/
```

