# Vulnerability: D-Link - Local File Inclusion
**Classification:** CWE-522
**Source:** Nuclei Template (`d-link-arbitary-fileread.yaml`)

## Description
D-Link is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/cgi-bin/webproc
```

