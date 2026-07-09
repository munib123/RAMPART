# Nuclei Template: Microsoft Access Database File - Detect
**Template ID:** mdb-database-file
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`mdb-database-file.yaml`)

## Vulnerability Information & PoC

## Description
Microsoft Access database file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{mdbPaths}} HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Accept-Language: en-US,en;q=0.9
```

## References
- https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.5-Testing_for_MS_Access.html
