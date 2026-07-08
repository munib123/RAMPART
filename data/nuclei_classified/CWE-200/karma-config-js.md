# Vulnerability: Karma Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`karma-config-js.yaml`)

## Description
Karma configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.config/karma.conf.js
GET {{BaseURL}}/karma.conf.js
```

