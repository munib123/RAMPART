# Vulnerability: Sharefile Login - Panel
**Classification:** SHAREFILE
**Source:** Nuclei Template (`sharefile-panel.yaml`)

## Description
ShareFile is a cloud-based file sharing and collaboration platform that provides secure access to files from anywhere.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Authentication/Login
```

