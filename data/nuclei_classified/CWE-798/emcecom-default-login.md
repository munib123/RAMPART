# Vulnerability: Dell EMC ECOM - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`emcecom-default-login.yaml`)

## Description
Dell EMC ECOM default login information "(admin:#1Password)" was discovered.

## Secure Mitigation
To resolve this issue, perform a "remsys" and "addsys" with no other operations occurring (reference the appropriate SMI-S provider documentation) and specify the new password when re-adding the array. If there are issues performing the "addsys" operation, it is recommended to restart the management server on each SP.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

