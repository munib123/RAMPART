# Vulnerability: Atlassian Connect Descriptor - Detect
**Classification:** ATLASSIAN
**Source:** Nuclei Template (`atlassian-connect-descriptor.yaml`)

## Description
The app descriptor is a JSON file ( atlassian-connect. json ) that describes the app to the Atlassian application. The descriptor includes general information for the app, as well as the modules that the app wants to use or extend.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/atlassian-connect.json
```

