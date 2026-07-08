# Vulnerability: Wix Takeover Detection
**Classification:** TAKEOVER
**Source:** Nuclei Template (`wix-takeover.yaml`)

## Description
This subdomain take over would only work on an edge case when the account was deleted. You will need a premium account (~ US$7) to test the take over.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

