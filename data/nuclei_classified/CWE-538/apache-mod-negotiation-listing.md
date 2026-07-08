# Vulnerability: Apache mod_negotiation - Pseudo Directory Listing
**Classification:** CWE-538
**Source:** Nuclei Template (`apache-mod-negotiation-listing.yaml`)

## Description
Detected Apache server with mod_negotiation and MultiViews enabled, exposing a pseudo directory listing when invalid Accept headers are sent to extensionless filenames.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{path}} HTTP/1.1
Host: {{Hostname}}
Accept: fake/fake
```

