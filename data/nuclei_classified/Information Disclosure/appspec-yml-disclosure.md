# Nuclei Template: Appspec YML/YAML - Detect
**Template ID:** appspec-yml-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`appspec-yml-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Appspec YML and YAML files are susceptible to information disclosure.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/appspec.yml
GET {{BaseURL}}/appspec.yaml
```

## References
- https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/appsec-yml-disclosure.json
