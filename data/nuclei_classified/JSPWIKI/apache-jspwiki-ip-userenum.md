# Vulnerability: Apache JSPWiki - User IP Enumeration
**Classification:** JSPWIKI
**Source:** Nuclei Template (`apache-jspwiki-ip-userenum.yaml`)

## Description
Enumerates the IP Address and users that is currently accessing an Apache JSPWiki web application, leading open source WikiWiki engine, feature-rich and built around standard JEE components (Java, servlets, JSP).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Wiki.jsp?page=SystemInfo
```

