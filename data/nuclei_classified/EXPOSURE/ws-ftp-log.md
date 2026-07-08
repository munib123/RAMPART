# Vulnerability: WS FTP File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`ws-ftp-log.yaml`)

## Description
WS_FTP software, which is a popular FTP (File Transfer Protocol) client used for transferring files between a local computer and a remote server has its log file exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ws_ftp.log
GET {{BaseURL}}/WS_FTP.LOG
```

