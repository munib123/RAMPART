# Vulnerability: Deprecated Feature-Policy Header - Detection
**Classification:** MISC
**Source:** Nuclei Template (`deprecated-feature-policy.yaml`)

## Description
Detected the presence of the deprecated Feature-Policy HTTP response header. The Feature-Policy header has been deprecated and replaced by the Permissions-Policy header. While Feature-Policy is still supported in some browsers for backward compatibility, it is recommended to migrate to Permissions-Policy for future-proofing web applications.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

