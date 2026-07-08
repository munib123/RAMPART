# Vulnerability: QiHang Media Web Digital Signage 3.0.9 - Cleartext Credentials Disclosure
**Classification:** CWE-522
**Source:** Nuclei Template (`qihang-media-disclosure.yaml`)

## Description
QiHang Media Web Digital Signage 3.0.9 suffers from a clear-text credentials disclosure vulnerability that allows an unauthenticated attacker to issue a request to an unprotected directory that hosts an XML file /xml/User/User.xml and obtain administrative login information that allows for a successful authentication bypass attack.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/xml/User/User.xml
```

