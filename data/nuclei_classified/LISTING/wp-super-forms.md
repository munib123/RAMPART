# Vulnerability: WordPress super-forms Plugin Directory Listing
**Classification:** LISTING
**Source:** Nuclei Template (`wp-super-forms.yaml`)

## Description
Searches for sensitive directories present in the super-forms plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/super-forms/
```

