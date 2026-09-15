# Nuclei Template: WordPress wp-config Detection
**Template ID:** wordpress-accessible-wpconfig
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`wordpress-accessible-wpconfig.yaml`)

## Vulnerability Information & PoC

## Description
WordPress `wp-config` was discovered. This file is remotely accessible and its content available for reading.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

