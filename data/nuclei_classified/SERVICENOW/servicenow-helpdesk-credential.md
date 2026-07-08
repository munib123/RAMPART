# Vulnerability: ServiceNow Helpdesk Credential Exposure
**Classification:** SERVICENOW
**Source:** Nuclei Template (`servicenow-helpdesk-credential.yaml`)

## Description
Detection of exposed credentials in help the help desk JS file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{RootURL}}/HelpTheHelpDesk.jsdbx
```

