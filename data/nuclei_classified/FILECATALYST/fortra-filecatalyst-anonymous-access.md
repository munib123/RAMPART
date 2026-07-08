# Vulnerability: Fortra FileCatalyst - Anonymous Access
**Classification:** FILECATALYST
**Source:** Nuclei Template (`fortra-filecatalyst-anonymous-access.yaml`)

## Description
Detects Fortra FileCatalyst web interfaces that allow anonymous or guest access. FileCatalyst is a managed file transfer solution, and anonymous access to its portal can expose sensitive files and configuration if not properly secured. This template checks for publicly accessible instances with guest or unauthenticated user functionality.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/workflow/jsp/downloadFiles.jsp
```

