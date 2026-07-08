# Vulnerability: viewLinc 5.1.2.367 - Carriage Return Line Feed Attack
**Classification:** CRLF
**Source:** Nuclei Template (`viewlinc-crlf-injection.yaml`)

## Description
viewLinc 5.1.2.367 (and sometimes 5.1.1.50) allows remote attackers to inject a carriage return line feed (CRLF) character into the responses returned by the product, which allows attackers to inject arbitrary HTTP headers into the response returned.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/%0ASet-Cookie:crlfinjection=crlfinjection
```

