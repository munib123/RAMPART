# Vulnerability: Azure Resource Manager Template - File Exposure
**Classification:** AZURE
**Source:** Nuclei Template (`azuredeploy-json.yaml`)

## Description
Azure Resource Manager deploy file is disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/azuredeploy.json
```

