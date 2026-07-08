# Vulnerability: EWEBS - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`ewebs-arbitrary-file-reading.yaml`)

## Description
EWEBS is vulnerable to local file inclusion and allows remote attackers to disclose the content of locally stored files via the 'Language_S' parameter supplied to the 'casmain.xgi' endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/casmain.xgi
```

