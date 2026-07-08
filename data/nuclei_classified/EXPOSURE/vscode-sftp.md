# Vulnerability: VSCode SFTP File Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`vscode-sftp.yaml`)

## Description
It discloses sensitive files created by vscode-sftp for VSCode, contains SFTP/SSH server details and credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sftp.json
GET {{BaseURL}}/.config/sftp.json
GET {{BaseURL}}/.vscode/sftp.json
```

