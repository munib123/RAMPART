# Vulnerability: Account Lockout Threshold Check
**Classification:** ACCOUNT-MANAGEMENT
**Source:** Nuclei Template (`account-lockout-threshold.yaml`)

## Description
Ensure the account lockout threshold is configured to 5 or fewer invalid login attempts to reduce the risk of brute-force attacks.

## Secure Mitigation
Set the lockout threshold using:
> net accounts /lockoutthreshold:5
or configure it via Local Security Policy under:
Account Lockout Policy → Account lockout threshold.

