# Vulnerability: Prettier - Ignore File Disclosure
**Classification:** PRETTIER
**Source:** Nuclei Template (`prettier-ignore-disclosure.yaml`)

## Description
The .prettierignore file is publicly accessible, potentially revealing project structure, sensitive file paths, and internal directory organization.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.prettierignore
GET {{BaseURL}}/.prettierrc
```

