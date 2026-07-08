# Vulnerability: Google FLoC Disabled
**Classification:** MISCELLANEOUS
**Source:** Nuclei Template (`google-floc-disabled.yaml`)

## Description
The detected website has decided to explicitly exclude itself from Google FLoC tracking.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

