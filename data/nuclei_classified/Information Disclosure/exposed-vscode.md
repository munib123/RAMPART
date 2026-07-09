# Nuclei Template: Visual Studio Code Directories - Detect
**Template ID:** exposed-vscode
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`exposed-vscode.yaml`)

## Vulnerability Information & PoC

## Description
Visual Studio Code directories were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.vscode/
```

