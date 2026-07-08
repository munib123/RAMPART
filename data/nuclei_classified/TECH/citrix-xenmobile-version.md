# Vulnerability: Citrix XenMobile Version - Detect
**Classification:** TECH
**Source:** Nuclei Template (`citrix-xenmobile-version.yaml`)

## Description
Template for XenMobile-detection (even if login-page is deactivated) and the specific version and rolling patch from js/app/init.js endpoint

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/js/app/init.js
```

