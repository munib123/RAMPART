# Vulnerability: phpwiki 1.5.4 - Cross-Site Scripting/Local File Inclusion
**Classification:** XSS
**Source:** Nuclei Template (`phpwiki-lfi.yaml`)

## Description
phpwiki 1.5.4 is vulnerable to cross-site scripting and local file inclusion, and allows remote unauthenticated attackers to include and return the content of locally stored files via the 'index.php' endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phpwiki/index.php/passwd
```

