# Vulnerability: ThinkPHP Errors - Sensitive Information Exposure
**Classification:** THINKPHP
**Source:** Nuclei Template (`thinkphp-errors.yaml`)

## Description
ThinkPHP error is leaking sensitive info.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

