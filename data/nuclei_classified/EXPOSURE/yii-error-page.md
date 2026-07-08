# Vulnerability: Yii Error Page - Detct
**Classification:** EXPOSURE
**Source:** Nuclei Template (`yii-error-page.yaml`)

## Description
Yii (An application framework to handle and manage errors) error page detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

