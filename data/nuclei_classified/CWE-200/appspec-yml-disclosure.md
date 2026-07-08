# Vulnerability: Appspec YML/YAML - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`appspec-yml-disclosure.yaml`)

## Description
Appspec YML and YAML files are susceptible to information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/appspec.yml
GET {{BaseURL}}/appspec.yaml
```

