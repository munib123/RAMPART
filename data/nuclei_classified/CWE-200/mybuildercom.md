# Vulnerability: MyBuilder.com User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mybuildercom.yaml`)

## Description
MyBuilder.com user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.mybuilder.com/profile/view/{{user}}
```

