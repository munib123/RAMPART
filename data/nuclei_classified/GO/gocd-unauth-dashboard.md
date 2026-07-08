# Vulnerability: GoCd Unauth Dashboard
**Classification:** GO
**Source:** Nuclei Template (`gocd-unauth-dashboard.yaml`)

## Description
GoCd Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/go/admin/pipelines/create?group=defaultGroup
```

