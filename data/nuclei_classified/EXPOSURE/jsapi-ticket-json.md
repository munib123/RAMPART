# Vulnerability: JsAPI Ticket Json
**Classification:** EXPOSURE
**Source:** Nuclei Template (`jsapi-ticket-json.yaml`)

## Description
JsAPI Ticket internal file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jsapi_ticket.json
```

