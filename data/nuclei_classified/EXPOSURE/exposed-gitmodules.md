# Vulnerability: .gitmodules File Exposed
**Classification:** EXPOSURE
**Source:** Nuclei Template (`exposed-gitmodules.yaml`)

## Description
The .gitmodules file was exposed on the web server as part of an accessible .git directory.This exposure indicated a misconfiguration that could have allowed attackers to explore the .git directory further and potentially reconstruct or download the full source code repository.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.gitmodules
```

