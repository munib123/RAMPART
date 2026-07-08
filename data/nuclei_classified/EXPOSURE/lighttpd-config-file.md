# Vulnerability: Lighttpd Config File - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`lighttpd-config-file.yaml`)

## Description
Lighttpd Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lighttpd.conf
```

