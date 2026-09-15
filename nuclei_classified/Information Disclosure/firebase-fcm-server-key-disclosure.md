# Nuclei Template: Firebase Cloud Messaging - Server Key Disclosure
**Template ID:** firebase-fcm-server-key-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`firebase-fcm-server-key-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Firebase Cloud Messaging (FCM) legacy server keys were identified in client-side files. These keys can be used to send push notifications to any device.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/firebase-messaging-sw.js
GET {{BaseURL}}/manifest.json
```

## References
- https://firebase.google.com/docs/cloud-messaging
