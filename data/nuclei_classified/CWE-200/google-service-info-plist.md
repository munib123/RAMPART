# Vulnerability: GoogleService-Info.plist - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`google-service-info-plist.yaml`)

## Description
The GoogleService-Info.plist file contains sensitive information about the Firebase project, including the Google App ID, Project ID, Client ID, Client Secret, and Reversed Client ID. This file is used to authenticate the Firebase SDK in iOS applications.

## Secure Mitigation
Remove the GoogleService-Info.plist file from the web root and restrict public access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/GoogleService-Info.plist
```

