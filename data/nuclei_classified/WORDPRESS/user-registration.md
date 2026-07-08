# Vulnerability: WordPress User Registration & Membership Plugin Detection
**Classification:** WORDPRESS
**Source:** Nuclei Template (`user-registration.yaml`)

## Description
Detected WordPress User Registration & Membership plugin and its version information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/user-registration/readme.txt
```

