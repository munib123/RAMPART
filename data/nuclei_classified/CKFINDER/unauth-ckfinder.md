# Vulnerability: CKFinder - Unauthenticated Exposure
**Classification:** CKFINDER
**Source:** Nuclei Template (`unauth-ckfinder.yaml`)

## Description
The CKFinder file manager was found to be exposed without authentication, allowing unauthenticated users to directly access its web interface. Due to this misconfiguration, attackers were able to browse server directories, upload arbitrary files, and manage existing files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ckfinder/ckfinder.html
```

