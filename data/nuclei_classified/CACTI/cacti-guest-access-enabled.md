# Vulnerability: Cacti - Guest User Access Enabled
**Classification:** CACTI
**Source:** Nuclei Template (`cacti-guest-access-enabled.yaml`)

## Description
Cacti instance has guest user access enabled, allowing unauthenticated users to access graph_view.php and potentially other resources.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/graph_view.php
GET {{BaseURL}}/cacti/graph_view.php
```

