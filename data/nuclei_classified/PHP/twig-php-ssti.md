# Vulnerability: Twig PHP <2.4.4 template engine - SSTI
**Classification:** PHP
**Source:** Nuclei Template (`twig-php-ssti.yaml`)

## Description
A vulnerability in Twig PHP allows remote attackers to cause the product to execute arbitrary commands via an SSTI vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/search?search_key=%7B%7B1337*1338%7D%7D
```

