# Vulnerability: View Yii Debugger Information
**Classification:** YII
**Source:** Nuclei Template (`yii-debugger.yaml`)

## Description
Detects potential exposure to Yii Debugger information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/debug/default/view.html
GET {{BaseURL}}/debug/default/view
GET {{BaseURL}}/frontend/web/debug/default/view
GET {{BaseURL}}/web/debug/default/view
GET {{BaseURL}}/sapi/debug/default/view
GET {{BaseURL}}/debug/default
```

