# Vulnerability: Microsoft Technet Community User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`microsoft-technet-community.yaml`)

## Description
Microsoft Technet Community user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://social.technet.microsoft.com/profile/{{user}}/
```

