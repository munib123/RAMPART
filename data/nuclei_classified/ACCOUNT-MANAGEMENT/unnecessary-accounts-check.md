# Vulnerability: Unnecessary Accounts Detection
**Classification:** ACCOUNT-MANAGEMENT
**Source:** Nuclei Template (`unnecessary-accounts-check.yaml`)

## Description
Identify local user accounts that deviate from default settings and could present security risks.

## Secure Mitigation
Delete unnecessary accounts by running:
- > net user [account_name] /delete
- Or disable them via Local Security Policy.

