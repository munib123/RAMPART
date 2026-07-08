# Vulnerability: CraftCMS Debug Methods Exposed
**Classification:** CRAFTCMS
**Source:** Nuclei Template (`craftcms-debug-exposure.yaml`)

## Description
Detected CraftCMS with devMode enabled, which exposed the Yii2 debug toolbar and sensitive information. This misconfiguration could have leaked database queries, session data, cookies, stack traces, CSRF tokens, and internal application details to unauthenticated users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/actions/debug/default/index
GET {{BaseURL}}/actions/debug/default/toolbar
GET {{BaseURL}}/actions/debug/default/view
```

