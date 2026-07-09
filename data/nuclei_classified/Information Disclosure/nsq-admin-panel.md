# Nuclei Template: NSQ Admin Panel - Detect
**Template ID:** nsq-admin-panel
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`nsq-admin-panel.yaml`)

## Vulnerability Information & PoC

## Description
NSQ admin panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://nsq.io/components/nsqd.html
