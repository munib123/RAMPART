# Nuclei Template: MAMP Server - Cross-Site Scripting
**Template ID:** mamp-server-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`mamp-server-xss.yaml`)

## Vulnerability Information & PoC

## Description
A Cross-Site Scripting (XSS) vulnerability exists in the default installation of MAMP server. The file `/Applications/MAMP/htdocs/index.php` is susceptible to malicious input, allowing attackers to inject JavaScript code that executes in the context of the victim's browser. This vulnerability can be exploited without prior authentication.

## Impact
Exploiting this vulnerability can allow attackers to execute arbitrary JavaScript in the victim's browser.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php/test"%20onmouseover="alert(document.domain);"%20style="font-size:100000px;background-color:white";
```

## Remediation
Implement input validation and output encoding to sanitize user inputs. Apply the vendor-supplied patch or upgrade MAMP to a version where the vulnerability is resolved.

## References
- https://octagon.net/blog/2022/01/26/mamp-server-preauth-xss-leading-to-host-compromise-0day/
