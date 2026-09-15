# Nuclei Template: FCM Server Key
**Template ID:** fcm-server-key
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-540
**Source:** Nuclei Template (`fcm-server-key.yaml`)

## Vulnerability Information & PoC

## Description
FCM Server Key is leaked.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://abss.me/posts/fcm-takeover
