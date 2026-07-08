# Vulnerability: Weblate Public Project - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`weblate-public-project-exposure.yaml`)

## Description
Weblate instance is publicly accessible. Public exposure of Weblate may lead to unauthorized access to translation projects, potential data leaks, credential exposure, or manipulation of open source localization data. Attackers can view available projects and access sensitive information if proper access controls are not implemented.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/projects/
```

