# Vulnerability: Apache httpd Config File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`httpd-config.yaml`)

## Description
Apache httpd configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/httpd.conf
```

