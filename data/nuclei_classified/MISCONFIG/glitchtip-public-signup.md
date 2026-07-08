# Vulnerability: Gitea Public Registration Enabled
**Classification:** MISCONFIG
**Source:** Nuclei Template (`glitchtip-public-signup.yaml`)

## Description
A misconfiguration in GlitchTip allows arbitrary users to sign up.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/settings/
```

