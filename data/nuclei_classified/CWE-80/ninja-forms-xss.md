# Vulnerability: Ninja Forms < 3.5.5 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`ninja-forms-xss.yaml`)

## Description
The Ninja Forms WordPress plugin before 3.5.5 does not escape an URL before outputting it back in an attribute, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin

## Secure Mitigation
Update the plugin to Latest version. Fixed in 3.5.5.

## Vulnerable Code Pattern / Exploit Payload
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

