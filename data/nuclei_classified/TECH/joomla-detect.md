# Vulnerability: Joomla! Detect
**Classification:** TECH
**Source:** Nuclei Template (`joomla-detect.yaml`)

## Description
Joomla! is a free and open-source content management system (CMS) for publishing content on websites.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/administrator/manifests/files/joomla.xml
GET {{BaseURL}}/language/en-GB/en-GB.xml
GET {{BaseURL}}/README.txt
GET {{BaseURL}}/modules/custom.xml
GET {{BaseURL}}
```

