# Nuclei Template: Ruijie Login Panel - Detect
**Template ID:** ruijie-information-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`ruijie-information-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Ruijie login panel was detected and leaks authentication credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/login.php
```

## References
- https://www.ruijienetworks.com/
- https://www.cnblogs.com/cHr1s/p/14499858.html
