# Vulnerability: DokuWiki Install Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`dokuwiki-installer.yaml`)

## Description
DokuWiki is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

