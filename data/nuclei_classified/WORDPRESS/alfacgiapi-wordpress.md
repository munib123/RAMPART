# Vulnerability: alfacgiapi
**Classification:** WORDPRESS
**Source:** Nuclei Template (`alfacgiapi-wordpress.yaml`)

## Description
Searches for sensitive directories present in the alfacgiapi plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-includes/ALFA_DATA/
GET {{BaseURL}}/wp-content/uploads/alm_templates/ALFA_DATA/alfacgiapi/
GET {{BaseURL}}/ALFA_DATA/alfacgiapi/
GET {{BaseURL}}/cgi-bin/ALFA_DATA/alfacgiapi/
```

