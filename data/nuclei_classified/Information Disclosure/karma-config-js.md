# Nuclei Template: Karma Configuration File - Detect
**Template ID:** karma-config-js
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`karma-config-js.yaml`)

## Vulnerability Information & PoC

## Description
Karma configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.config/karma.conf.js
GET {{BaseURL}}/karma.conf.js
```

