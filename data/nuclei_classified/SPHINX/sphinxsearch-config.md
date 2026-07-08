# Vulnerability: Sphinx Search Config - Exposure
**Classification:** SPHINX
**Source:** Nuclei Template (`sphinxsearch-config.yaml`)

## Description
sphinx.conf file contains SQL credentials and is publicly accessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/development.sphinx.conf
GET {{BaseURL}}/config/production.sphinx.conf
GET {{BaseURL}}/configs/sphinx.conf
GET {{BaseURL}}/search/configs/sphinx.conf
GET {{BaseURL}}/sphinx.conf
GET {{BaseURL}}/sphinx/sphinx.conf
GET {{BaseURL}}/sphinxsearch/sphinx.conf
```

