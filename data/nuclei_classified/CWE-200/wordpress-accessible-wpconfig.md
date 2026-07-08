# Vulnerability: WordPress wp-config Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`wordpress-accessible-wpconfig.yaml`)

## Description
WordPress `wp-config` was discovered. This file is remotely accessible and its content available for reading.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

