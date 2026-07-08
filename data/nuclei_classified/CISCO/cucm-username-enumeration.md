# Vulnerability: Cisco Unified Communications Manager - User Enumeration
**Classification:** CISCO
**Source:** Nuclei Template (`cucm-username-enumeration.yaml`)

## Description
Cisco Unified Call Manager is vulnerable to username enumeration. This template enumerates valid usernames and emails from the Cisco UCM UDS API.

## Secure Mitigation
To mitigate this, enable Contact Search Authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cucm-uds/users
```

