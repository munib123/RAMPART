# Vulnerability: MAMP Server - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`mamp-server-xss.yaml`)

## Description
A Cross-Site Scripting (XSS) vulnerability exists in the default installation of MAMP server. The file `/Applications/MAMP/htdocs/index.php` is susceptible to malicious input, allowing attackers to inject JavaScript code that executes in the context of the victim's browser. This vulnerability can be exploited without prior authentication.

## Secure Mitigation
Implement input validation and output encoding to sanitize user inputs. Apply the vendor-supplied patch or upgrade MAMP to a version where the vulnerability is resolved.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/test"%20onmouseover="alert(document.domain);"%20style="font-size:100000px;background-color:white";
```

