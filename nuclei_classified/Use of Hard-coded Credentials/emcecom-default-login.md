# Nuclei Template: Dell EMC ECOM - Default Login
**Template ID:** emcecom-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`emcecom-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Dell EMC ECOM default login information "(admin:#1Password)" was discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

## Remediation
To resolve this issue, perform a "remsys" and "addsys" with no other operations occurring (reference the appropriate SMI-S provider documentation) and specify the new password when re-adding the array. If there are issues performing the "addsys" operation, it is recommended to restart the management server on each SP.

## References
- https://www.dell.com/support/kbdoc/en-za/000171270/vipr-controller-operation-denied-by-clariion-array-you-are-not-privileged-to-perform-the-requested-operation
