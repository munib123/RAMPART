# Vulnerability: Liferay /api/jsonws - API Exposed
**Classification:** LIFERAY
**Source:** Nuclei Template (`liferay-jsonws.yaml`)

## Description
Liferay /api/jsonws - API is Exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/jsonws
```

