# Vulnerability: LaunchDarkly - Detect
**Classification:** TECH
**Source:** Nuclei Template (`launchdarkly-detect.yaml`)

## Description
Detects the presence of LaunchDarkly, a feature management and feature flag platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

