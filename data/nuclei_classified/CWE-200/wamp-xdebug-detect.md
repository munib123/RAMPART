# Vulnerability: WAMP Xdebug - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wamp-xdebug-detect.yaml`)

## Description
WAMP Xdebug was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?phpinfo=-1
```

