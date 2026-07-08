# Vulnerability: NPM .npmignore File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`npmignore-disclosure.yaml`)

## Description
Detected NPM .npmignore configuration file, potentially exposing excluded files and project structure information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.npmignore
GET {{BaseURL}}/node_modules/.npmignore
GET {{BaseURL}}/src/.npmignore
GET {{BaseURL}}/api/.npmignore
GET {{BaseURL}}/backend/.npmignore
```

