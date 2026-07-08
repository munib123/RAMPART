# Vulnerability: Ensure Strong Password Hashing Algorithm is Configured
**Classification:** CIS
**Source:** Nuclei Template (`strong-password-hashing.yaml`)

## Description
The ENCRYPT_METHOD setting in /etc/login.defs specifies the algorithm used to hash passwords.It should be set to SHA512 or yescrypt, as weaker algorithms may expose passwords to brute-force attacks.

## Secure Mitigation
Edit /etc/login.defs and set ENCRYPT_METHOD to either SHA512 or yescrypt.Verify with: grep -Pi -- '^\h*ENCRYPT_METHOD\h+(SHA512|yescrypt)\b' /etc/login.defs

