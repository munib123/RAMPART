# Nuclei Template: Fronsetiav1.1 - Cross-Site Scripting
**Template ID:** fronsetiav-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`fronsetiav-xss.yaml`)

## Vulnerability Information & PoC

## Description
The fronsetiav1.1 application is vulnerable to a Reflected XSS attack through the show_operations.jsp endpoint. An attacker can inject malicious scripts via the WSDL Location input, which is executed in the victim's browser due to improper input sanitization. This allows attackers to execute arbitrary JavaScript, potentially stealing sensitive data or performing phishing attacks..

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/show_operations.jsp?Fronsetia_WSDL=%22%3E%3Cimg%2Bsrc%3Dx%20onerror%3Dalert(document.domain)%3E
```

## References
- https://seclists.org/fulldisclosure/2024/Nov/10
- https://packetstormsecurity.com/files/182764/fronsetia-1.1-Cross-Site-Scripting.html
- https://msecureltd.blogspot.com/2024/11/friday-fun-pentest-series-14-reflected.html
