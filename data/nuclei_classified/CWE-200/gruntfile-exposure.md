# Vulnerability: Gruntfile Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gruntfile-exposure.yaml`)

## Description
Gruntfile configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Gruntfile.js
GET {{BaseURL}}/Gruntfile.coffee
```

