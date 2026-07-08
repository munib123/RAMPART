# Vulnerability: Copyparty v1.8.6 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`copyparty-xss.yaml`)

## Description
Copyparty is a portable file server. Versions prior to 1.8.6 are subject to a reflected cross-site scripting (XSS) Attack. The vulnerability in the application's web interface could allow an attacker to execute malicious javascript code by tricking users into accessing a malicious link.

## Secure Mitigation
Upgrade to the latest version to mitigate this vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?hc=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

