# Vulnerability: Atlassian Confluence XSLT Macro - Server-Side Request Forgery
**Classification:** CWE-611,CWE-918
**Source:** Nuclei Template (`confluence-xslt-macro-ssrf.yaml`)

## Description
Atlassian Confluence Data Center and Server include an XSLT macro feature that may be vulnerable to Server-Side Request Forgery (SSRF). By leveraging the ability of the XSLT macro to access external resources, attackers can potentially cause the server to make HTTP requests to arbitrary URLs. This can allow internal network scanning, access to sensitive systems, or exposure of internal information.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/rest/tinymce/1/macro/preview
POST {{BaseURL}}/rest/api/content/macro/preview
POST {{BaseURL}}/rest/tinymce/1/macro/preview
POST {{BaseURL}}/rest/api/content/macro/preview
```

