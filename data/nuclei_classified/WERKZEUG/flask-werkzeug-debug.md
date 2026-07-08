# Vulnerability: Flask Werkzeug Debugger Exposure
**Classification:** WERKZEUG
**Source:** Nuclei Template (`flask-werkzeug-debug.yaml`)

## Description
Flask Werkzeug Debugger is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

