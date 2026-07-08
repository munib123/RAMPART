# Vulnerability: MyFitnessPal Community User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`myfitnesspal-community.yaml`)

## Description
MyFitnessPal Community user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://community.myfitnesspal.com/en/profile/{{user}}
```

