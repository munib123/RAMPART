# Vulnerability: Samsung WLAN AP WEA453e - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`samsung-wlan-ap-xss.yaml`)

## Description
Samsung WLAN AP WEA453e router contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/%3Cscript%3Ealert(document.domain)%3C/script%3E
```

