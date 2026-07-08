# Vulnerability: SECUI WAF Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`secui-waf-detect.yaml`)

## Description
SECUI WAF panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/static/login/favicon.ico
```

