# Vulnerability: Azkaban Web Client Default Credential
**Classification:** CWE-798
**Source:** Nuclei Template (`azkaban-default-login.yaml`)

## Description
Azkaban is a batch workflow job scheduler created at LinkedIn to run Hadoop jobs.  Default web client credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=login&username={{username}}&password={{password}}
```

