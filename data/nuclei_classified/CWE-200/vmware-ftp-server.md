# Vulnerability: VMware FTP Server Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmware-ftp-server.yaml`)

## Description
VMware FTP Server login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

