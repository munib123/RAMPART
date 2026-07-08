# Vulnerability: Liferay - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`liferay-resource-leak.yaml`)

## Description
Liferay is vulnerable to local file inclusion in the I18n Servlet because it leaks information via sending an HTTP request to /[language]/[resource];.js (also .jsp works).

## Secure Mitigation
Update Liferay to the latest version

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/en/WEB-INF/web.xml;.js
```

