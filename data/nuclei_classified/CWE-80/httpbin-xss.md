# Vulnerability: HTTPBin - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`httpbin-xss.yaml`)

## Description
HTTPBin contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/base64/PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
```

