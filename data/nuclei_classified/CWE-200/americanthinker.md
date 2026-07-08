# Vulnerability: AmericanThinker User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`americanthinker.yaml`)

## Description
AmericanThinker user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.americanthinker.com/author/{{user}}/
```

