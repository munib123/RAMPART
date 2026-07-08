# Vulnerability: JetBrains TeamCity - Guest User Access Enabled
**Classification:** CWE-200
**Source:** Nuclei Template (`teamcity-guest-login-enabled.yaml`)

## Description
TeamCity provides the ability to turn on the guest login allowing anonymous access to the TeamCity UI.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /guestLogin.html?guest=1 HTTP/1.1
Host: {{Hostname}}
```

