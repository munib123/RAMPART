# Nuclei Template: JetBrains TeamCity - Registration Enabled
**Template ID:** teamcity-registration-enabled
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`teamcity-registration-enabled.yaml`)

## Vulnerability Information & PoC

## Description
JetBrains TeamCity allows all visitors to register due to a misconfiguration.

## Steps to reproduce / Exploit Payload
```http
GET /registerUser.html?init=1 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://ph33r.medium.com/misconfig-in-teamcity-panel-lead-to-auth-bypass-in-apache-org-0day-146f6a1a4e2b
