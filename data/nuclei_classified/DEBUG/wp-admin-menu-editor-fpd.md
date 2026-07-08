# Vulnerability: Admin Menu Editor - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-admin-menu-editor-fpd.yaml`)

## Description
Admin Menu Editor WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/admin-menu-editor/menu-editor.php
```

