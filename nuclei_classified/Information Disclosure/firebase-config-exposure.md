# Nuclei Template: Firebase Configuration File - Detect
**Template ID:** firebase-config-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`firebase-config-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Firebase configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/public/config.js
GET {{BaseURL}}/config.js
```

## References
- https://github.com/firebase/firebaseui-web/blob/master/demo/public/sample-config.js
