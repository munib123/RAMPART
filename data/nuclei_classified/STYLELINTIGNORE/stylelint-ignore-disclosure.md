# Vulnerability: Stylelint - Ignore File Disclosure
**Classification:** STYLELINTIGNORE
**Source:** Nuclei Template (`stylelint-ignore-disclosure.yaml`)

## Description
The .stylelintignore file is publicly accessible, potentially revealing project structure, sensitive file paths, and internal directory organization.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.stylelintignore
```

