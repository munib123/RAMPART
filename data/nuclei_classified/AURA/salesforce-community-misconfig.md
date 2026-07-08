# Vulnerability: Salesforce Community Misconfiguration
**Classification:** AURA
**Source:** Nuclei Template (`salesforce-community-misconfig.yaml`)

## Description
A misconfigured Salesforce Community may lead to sensitive Salesforce data being exposed to anyone on the internet. Anonymous users can query objects that contain sensitive information such as customer lists, support cases, and employee email addresses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{RootURL}}/s/
POST {{RootURL}}/s/sfsites/aura
```

