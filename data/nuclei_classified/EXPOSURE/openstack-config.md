# Vulnerability: Openstack - Infomation Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`openstack-config.yaml`)

## Description
Openstack exposing Configuration or settings related to the Swift object storage system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/info
GET {{BaseURL}}/v1/info
```

