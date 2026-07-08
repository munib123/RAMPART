# Vulnerability: PostHog Browser RUM - Detect
**Classification:** TECH
**Source:** Nuclei Template (`posthog-rum-detect.yaml`)

## Description
Detects PostHog Product Analytics & RUM (Real User Monitoring) SDK artifacts in HTML responses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

