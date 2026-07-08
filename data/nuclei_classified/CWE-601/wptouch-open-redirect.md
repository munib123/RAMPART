# Vulnerability: WordPress WPtouch 3.x - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`wptouch-open-redirect.yaml`)

## Description
WordPress WPtouch plugin 3.x contains an open redirect vulnerability. The plugin fails to properly sanitize user-supplied input. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?wptouch_switch=desktop&redirect=https://interact.sh/
```

