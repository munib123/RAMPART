# Vulnerability: Roundcube Log Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`roundcube-log-disclosure.yaml`)

## Description
Roundcube Log file was disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{roundcube_path}}
```

