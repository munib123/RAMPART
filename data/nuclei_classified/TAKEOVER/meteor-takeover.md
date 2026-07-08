# Vulnerability: Meteor subdomain takeover
**Classification:** TAKEOVER
**Source:** Nuclei Template (`meteor-takeover.yaml`)

## Description
Meteor takeover was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

