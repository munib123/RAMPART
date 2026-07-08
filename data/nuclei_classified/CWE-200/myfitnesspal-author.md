# Vulnerability: MyFitnessPal Author User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`myfitnesspal-author.yaml`)

## Description
MyFitnessPal Author user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://blog.myfitnesspal.com/author/{{user}}/
```

