# Vulnerability: User Role Editor - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-user-role-editor-fpd.yaml`)

## Description
User Role Editor WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/user-role-editor/user-role-editor.php
```

