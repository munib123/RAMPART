# Vulnerability: Visual Studio Code launch.json Exposure
**Classification:** VSCODE
**Source:** Nuclei Template (`vscode-launch.yaml`)

## Description
The .vscode/launch.json file, used by Visual Studio Code for debugging configurations, is publicly accessible. This file often contains sensitive information such as local file paths, runtime arguments, environment variables, and sometimes hardcoded credentials or access tokens.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.vscode/launch.json
```

