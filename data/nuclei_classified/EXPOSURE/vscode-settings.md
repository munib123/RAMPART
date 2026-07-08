# Vulnerability: Visual Studio Code Settings - Credential Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`vscode-settings.yaml`)

## Description
Detected exposed Visual Studio Code configuration files that were accessible over HTTP, which could have led to credential leakage or sensitive workspace disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.vscode/settings.json
GET {{BaseURL}}/settings.json
GET {{BaseURL}}/.vscode/launch.json
GET {{BaseURL}}/.vscode/tasks.json
GET {{BaseURL}}/.vscode-server/data/Machine/settings.json
```

