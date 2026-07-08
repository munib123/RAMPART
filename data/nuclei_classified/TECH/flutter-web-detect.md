# Vulnerability: Flutter Web Application - Detect
**Classification:** TECH
**Source:** Nuclei Template (`flutter-web-detect.yaml`)

## Description
Detect flutter web apps looking for flutter_bootstrap.js,main.dart.js and flutter_service_worker.js files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/flutter_service_worker.js
GET {{BaseURL}}/main.dart.js
GET {{BaseURL}}/flutter_bootstrap.js
```

