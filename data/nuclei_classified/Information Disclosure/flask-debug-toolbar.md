# Nuclei Template: Flask Debug Toolbar - Exposure
**Template ID:** flask-debug-toolbar
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`flask-debug-toolbar.yaml`)

## Vulnerability Information & PoC

## Description
Detected Flask Debug Toolbar was exposed in production, potentially leaking sensitive application information, SQL queries, request data, and configuration details.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://flask-debugtoolbar.readthedocs.io/
- https://github.com/flask-debugtoolbar/flask-debugtoolbar
