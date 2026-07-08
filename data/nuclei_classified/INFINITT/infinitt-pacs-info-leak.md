# Vulnerability: Infinitt PACS System - Information Disclosure
**Classification:** INFINITT
**Source:** Nuclei Template (`infinitt-pacs-info-leak.yaml`)

## Description
Infinitt PACS System is vulnerable to an Information Disclosure vulnerability. By sending a crafted request, an attacker can obtain sensitive user information, including passwords.

## Secure Mitigation
Ensure that access to the WebUserLogin.asmx endpoint is restricted and requires authentication. Implement proper access controls and input validation to prevent unauthorized access to sensitive user information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin
```

