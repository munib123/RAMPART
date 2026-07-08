# Vulnerability: Matomo (Piwik) RUM - Tech Detect
**Classification:** TECH
**Source:** Nuclei Template (`matomo-rum-detect.yaml`)

## Description
Detects Matomo (formerly Piwik) Web Analytics & RUM artifacts. Identifies Standard Tracking, Image Tracking, Tag Manager, and Cloud instances using strict matching.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

