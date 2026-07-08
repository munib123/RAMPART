# Vulnerability: Haproxy Config - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`haproxy-config-file.yaml`)

## Description
Haproxy Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/haproxy.cfg
```

