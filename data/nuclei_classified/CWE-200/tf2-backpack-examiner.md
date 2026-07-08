# Vulnerability: TF2 Backpack Examiner User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tf2-backpack-examiner.yaml`)

## Description
TF2 Backpack Examiner user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://www.tf2items.com/id/{{user}}/
```

