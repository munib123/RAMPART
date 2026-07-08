# Vulnerability: Somansa DLP Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`somansa-dlp-detect.yaml`)

## Description
Somansa DLP login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/DLPCenter/loginform.sms
GET {{BaseURL}}/DLPCenter/images/favicon.ico
```

