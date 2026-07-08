# Vulnerability: Fronsetiav1.1 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`fronsetiav-xss.yaml`)

## Description
The fronsetiav1.1 application is vulnerable to a Reflected XSS attack through the show_operations.jsp endpoint. An attacker can inject malicious scripts via the WSDL Location input, which is executed in the victim's browser due to improper input sanitization. This allows attackers to execute arbitrary JavaScript, potentially stealing sensitive data or performing phishing attacks..

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/show_operations.jsp?Fronsetia_WSDL=%22%3E%3Cimg%2Bsrc%3Dx%20onerror%3Dalert(document.domain)%3E
```

