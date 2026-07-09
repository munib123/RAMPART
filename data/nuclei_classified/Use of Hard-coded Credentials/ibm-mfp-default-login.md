# Nuclei Template: IBM MobileFirst Foundation - Default Credentials
**Template ID:** ibm-mfp-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** Critical
**CWE:** CWE-798
**Source:** Nuclei Template (`ibm-mfp-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected IBM MobileFirst Foundation Operations Console was found using default credentials. The administration REST API exposes full control over mobile application backends including adapter management, push notification infrastructure, OAuth security configuration, and application authenticity enforcement.

## Steps to reproduce / Exploit Payload
```http
GET /mfpadmin/management-apis/2.0/runtimes HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
Accept: application/json
```

## References
- https://www.ibm.com/docs/en/mfp/8.0?topic=console-mobilefirst-operations
- https://mobilefirstplatform.ibmcloud.com/tutorials/en/foundation/8.0/installation-configuration/production/server-configuration/
