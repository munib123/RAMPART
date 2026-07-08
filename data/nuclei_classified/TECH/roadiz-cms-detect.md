# Vulnerability: Roadiz CMS - Detect
**Classification:** TECH
**Source:** Nuclei Template (`roadiz-cms-detect.yaml`)

## Description
Roadiz is a modern CMS based on Symfony components with a focus on handling complex content structures. This template detects Roadiz CMS installations by checking for generator meta tags.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

