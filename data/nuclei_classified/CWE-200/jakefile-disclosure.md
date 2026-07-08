# Vulnerability: Jakefile Build Configuration - Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`jakefile-disclosure.yaml`)

## Description
Detected Jakefile build configuration was found to be exposed, potentially having contained sensitive information including database credentials, API keys, and server configurations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Jakefile
GET {{BaseURL}}/Jakefile.js
```

