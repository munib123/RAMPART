# Vulnerability: Public .idea Folder containing files with sensitive data
**Classification:** PHPSTORM
**Source:** Nuclei Template (`idea-folder-exposure.yaml`)

## Description
Searches for .idea Folder by querying the /.idea and a few other files with sensitive data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.idea/deployment.xml
GET {{BaseURL}}/.idea/workspace.xml
```

