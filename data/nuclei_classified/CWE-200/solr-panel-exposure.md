# Vulnerability: Apache Solr Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`solr-panel-exposure.yaml`)

## Description
Apache Solr admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/solr/
GET {{BaseURL}}
```

