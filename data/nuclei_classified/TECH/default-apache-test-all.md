# Vulnerability: Apache HTTP Server Test Page
**Classification:** TECH
**Source:** Nuclei Template (`default-apache-test-all.yaml`)

## Description
Detects default installations of apache (not just apache2 or installations on CentOS)

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

