# Vulnerability: RockMongo 1.1.8 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`rockmongo-xss.yaml`)

## Description
RockMongo 1.1.8 contains a cross-site scripting vulnerability which allows attackers to inject arbitrary JavaScript into the response returned by the application.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/index.php?action=login.index
```

