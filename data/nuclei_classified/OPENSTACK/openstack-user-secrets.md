# Vulnerability: OpenStack User Secrets Exposure
**Classification:** OPENSTACK
**Source:** Nuclei Template (`openstack-user-secrets.yaml`)

## Description
Internal user_secrets.yml file is exposed in OpenStack.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user_secrets.yml
GET {{BaseURL}}/user_secrets.yml.old
```

