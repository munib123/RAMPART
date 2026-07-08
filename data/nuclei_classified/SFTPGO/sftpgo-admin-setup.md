# Vulnerability: SFTPGo Admin - Setup
**Classification:** SFTPGO
**Source:** Nuclei Template (`sftpgo-admin-setup.yaml`)

## Description
SFTPGo Admin Password setup page has been exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web/admin/setup
```

