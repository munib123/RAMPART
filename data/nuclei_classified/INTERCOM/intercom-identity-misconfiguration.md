# Vulnerability: Intercom Identity Verification Misconfiguration
**Classification:** INTERCOM
**Source:** Nuclei Template (`intercom-identity-misconfiguration.yaml`)

## Description
Identity Verification is not setup on the Intercom widget, allowing an attacker to impersonate a user and access their chat history.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
POST https://api-iam.intercom.io/messenger/web/ping
```

