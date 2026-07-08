# Vulnerability: JustBoil.me Images Plugin - Exposed Image Upload
**Classification:** JUSTBOIL
**Source:** Nuclei Template (`justboil-me-image-upload.yaml`)

## Description
JustBoil.me Images Plugin for TinyMCE contains an exposed dialog interface that could lead to potential security vulnerabilities. The plugin's dialog-v4.htm file is accessible without proper access controls, which may allow unauthorized access to image upload functionality.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plugins/generic/tinymce/plugins/justboil.me/dialog-v4.htm
```

