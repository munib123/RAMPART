# Vulnerability: Firebase Cloud Messaging - Server Key Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`firebase-fcm-server-key-disclosure.yaml`)

## Description
Detected Firebase Cloud Messaging (FCM) legacy server keys were identified in client-side files. These keys can be used to send push notifications to any device.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/firebase-messaging-sw.js
GET {{BaseURL}}/manifest.json
```

