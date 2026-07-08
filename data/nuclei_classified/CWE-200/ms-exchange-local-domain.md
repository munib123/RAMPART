# Vulnerability: Microsoft Exchange Autodiscover - Local Domain Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`ms-exchange-local-domain.yaml`)

## Description
Microsoft Exchange is prone to a local domain exposure using the Autodiscover v2 endpoint.

## Secure Mitigation
Restrict access to the Autodiscover service or configure it to not expose local domain information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/autodiscover/autodiscover.json?Protocol=ActiveSync&Email=user@domain.tld&RedirectCount=1
```

