# Vulnerability: .htdeployment - Files Tree Cache File
**Classification:** FILES
**Source:** Nuclei Template (`ht-deployment.yaml`)

## Description
FTP Deployment cache file that contains whole files structure with paths to potentially sensitive files.

## Secure Mitigation
Block access to the file using `.htaccess` on the server. The best-practise is to block all the folders/files beginning with `.` except `.well-known` folder.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.htdeployment
GET {{BaseURL}}/.deployment
```

