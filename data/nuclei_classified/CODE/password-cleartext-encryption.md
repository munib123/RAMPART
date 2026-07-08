# Vulnerability: Store Passwords Using Reversible Encryption Check
**Classification:** CODE
**Source:** Nuclei Template (`password-cleartext-encryption.yaml`)

## Description
Ensure the "Store passwords using reversible encryption" policy is set to Disabled. If enabled, it can allow stored passwords to be retrieved in plaintext, posing a serious security risk.

## Secure Mitigation
Disable this policy using one of the following methods:
- Command Line: Export the security configuration, set ClearTextPassword=0, and reapply it using secedit.
- GUI: Open Local Security Policy → Account Policies → Password Policy → "Store passwords using reversible encryption" and set it to Disabled.

