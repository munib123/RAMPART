# Vulnerability: Tagged User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tagged.yaml`)

## Description
Tagged user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://secure.tagged.com/{{user}}
```

