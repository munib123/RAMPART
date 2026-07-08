# Vulnerability: Apache Sling - Detect
**Classification:** APACHE
**Source:** Nuclei Template (`apache-sling-detect.yaml`)

## Description
Detects a Apache Sling, a Java-based web framework designed for content-centric applications, using a RESTful approach to map URL requests directly to resources in a Java Content Repository (JCR).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/starter.html
```

