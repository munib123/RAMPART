# Vulnerability: CentOS EOL - Detect
**Classification:** CENTOS
**Source:** Nuclei Template (`centos-eol.yaml`)

## Description
Detected CentOS systems that had reached End-of-Life (EOL) status by identifying outdated version information in HTTP response.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

