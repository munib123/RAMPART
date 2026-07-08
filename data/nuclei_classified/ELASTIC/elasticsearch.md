# Vulnerability: ElasticSearch Information Disclosure
**Classification:** ELASTIC
**Source:** Nuclei Template (`elasticsearch.yaml`)

## Description
Internal information is exposed in elasticsearch to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?pretty
GET {{BaseURL}}/_cat/indices?v
GET {{BaseURL}}/_all/_search
GET {{BaseURL}}/_cluster/health?pretty
```

