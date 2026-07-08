# Vulnerability: ThinkPHP - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`thinkphp-detect.yaml`)

## Description
ThinkPHP was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/?s={{randstr}}&c={{randstr}}&a={{randstr}}&m={{randstr}}
```

