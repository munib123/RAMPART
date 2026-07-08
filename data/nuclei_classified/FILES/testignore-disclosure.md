# Vulnerability: Testignore - File Disclosure
**Classification:** FILES
**Source:** Nuclei Template (`testignore-disclosure.yaml`)

## Description
Detected that the .testignore file was publicly accessible, potentially revealing the project structure, sensitive file paths, and internal directory organization.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.testignore
```

