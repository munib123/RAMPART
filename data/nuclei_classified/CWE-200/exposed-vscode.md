# Vulnerability: Visual Studio Code Directories - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-vscode.yaml`)

## Description
Visual Studio Code directories were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.vscode/
```

