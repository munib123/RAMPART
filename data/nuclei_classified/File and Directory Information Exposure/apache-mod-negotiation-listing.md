# Nuclei Template: Apache mod_negotiation - Pseudo Directory Listing
**Template ID:** apache-mod-negotiation-listing
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Low
**CWE:** CWE-538
**Source:** Nuclei Template (`apache-mod-negotiation-listing.yaml`)

## Vulnerability Information & PoC

## Description
Detected Apache server with mod_negotiation and MultiViews enabled, exposing a pseudo directory listing when invalid Accept headers are sent to extensionless filenames.

## Steps to reproduce / Exploit Payload
```http
GET {{path}} HTTP/1.1
Host: {{Hostname}}
Accept: fake/fake
```

## References
- https://www.acunetix.com/vulnerabilities/web/apache-mod_negotiation-filename-bruteforcing/
- https://cwe.mitre.org/data/definitions/538.html
