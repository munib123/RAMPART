# Vulnerability: NetMizer LogManagement System Data - Directory Exposure
**Classification:** NETMIZER
**Source:** Nuclei Template (`netmizer-data-listing.yaml`)

## Description
Directory Exposure vulnerability in the NetMizer log management system of Beijing Lingzhou Network Technology Co., Ltd. Due to the loose control of /data, attackers can use this vulnerability to obtain sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/data/
```

