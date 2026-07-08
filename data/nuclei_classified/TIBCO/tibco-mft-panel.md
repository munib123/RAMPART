# Vulnerability: TIBCO Managed File Transfer - Panel
**Classification:** TIBCO
**Source:** Nuclei Template (`tibco-mft-panel.yaml`)

## Description
TIBCO Managed File Transfer Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cfcc/login/login.jsp
GET {{BaseURL}}/login/login.jsp
```

