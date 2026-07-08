# Vulnerability: Pyramid Debug Toolbar
**Classification:** PYRAMID
**Source:** Nuclei Template (`pyramid-debug-toolbar.yaml`)

## Description
Pyramid Debug Toolbar provides a debug toolbar useful while you are developing your Pyramid application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_debug_toolbar/
```

