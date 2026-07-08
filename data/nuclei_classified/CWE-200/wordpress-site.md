# Vulnerability: WordPress Site Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wordpress-site.yaml`)

## Description
WordPress site name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.wordpress.com
```

