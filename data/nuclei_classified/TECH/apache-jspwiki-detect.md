# Vulnerability: Apache JSPWiki - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-jspwiki-detect.yaml`)

## Description
Detects a Apache JSPWiki web application, leading open source WikiWiki engine, feature-rich and built around standard JEE components (Java, servlets, JSP).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

