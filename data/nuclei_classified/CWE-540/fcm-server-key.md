# Vulnerability: FCM Server Key
**Classification:** CWE-540
**Source:** Nuclei Template (`fcm-server-key.yaml`)

## Description
FCM Server Key is leaked.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

