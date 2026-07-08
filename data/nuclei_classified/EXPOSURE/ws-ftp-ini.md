# Vulnerability: WS FTP File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`ws-ftp-ini.yaml`)

## Description
WS FTP file is disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ws_ftp.ini
```

