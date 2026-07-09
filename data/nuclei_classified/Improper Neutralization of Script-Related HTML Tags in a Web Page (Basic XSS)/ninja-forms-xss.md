# Nuclei Template: Ninja Forms < 3.5.5 - Cross-Site Scripting
**Template ID:** ninja-forms-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`ninja-forms-xss.yaml`)

## Vulnerability Information & PoC

## Description
The Ninja Forms WordPress plugin before 3.5.5 does not escape an URL before outputting it back in an attribute, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin

## Impact
Attackers can potentially exploit this XSS vulnerability to gain unauthorized access to sensitive information.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /{{path}} HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Update the plugin to Latest version. Fixed in 3.5.5.

## References
- https://wpscan.com/vulnerability/ba6fa3d6-e3f7-449a-bd78-d57c26a67aa6/
