# Vulnerability: Visual Studio Code - Slnx.SQLite File Disclosure
**Classification:** VSCODE
**Source:** Nuclei Template (`vscode-slnx-sqlite-disclosure.yaml`)

## Description
Visual Studio Code and Visual Studio may create slnx.sqlite database files that contain solution metadata, project information, and potentially sensitive configuration data. If these files are accessible on a web server, they can expose internal project structure and development environment details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/slnx.sqlite
GET {{BaseURL}}/.vs/slnx.sqlite
```

