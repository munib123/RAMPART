# Vulnerability: Aishu AnyShare - Information Disclosure
**Classification:** AISHU-ANYSHARE
**Source:** Nuclei Template (`aishu-anyshare-info-exposure.yaml`)

## Description
Aishu AnyShare intelligent content management platform Usrm_GetAllUsers interface has an information disclosure vulnerability, and unauthenticated attackers can obtain sensitive information such as usernames and passwords. You can log in to the background and put the system in a highly insecure state.

## Secure Mitigation
Ensure that the endpoint is protected and only accessible by authenticated and authorized users. Implement proper access controls and validate user permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/ShareMgnt/Usrm_GetAllUsers HTTP/1.1
Host: {{Hostname}}

[1,100]
```

