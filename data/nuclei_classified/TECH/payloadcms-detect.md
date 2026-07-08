# Vulnerability: PayloadCMS - Detect
**Classification:** TECH
**Source:** Nuclei Template (`payloadcms-detect.yaml`)

## Description
PayloadCMS panel was detected. PayloadCMS is an open-source, headless CMS and application framework built with Node.js, React, and TypeScript.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/admin/login
```

