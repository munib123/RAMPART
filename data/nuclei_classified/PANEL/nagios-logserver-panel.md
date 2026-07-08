# Vulnerability: Nagios Log Server - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`nagios-logserver-panel.yaml`)

## Description
Detects the presence of Nagios Log Server by identifying specific response patterns, HTTP headers, or unique page elements.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

