# Vulnerability: Minimum Administrator Group Membership Check
**Classification:** ACCOUNT-MANAGEMENT
**Source:** Nuclei Template (`admin-group-minimal.yaml`)

## Description
Ensure that only essential accounts are members of the Administrators group. Excess or unnecessary accounts can increase the system's vulnerability to compromise.

## Secure Mitigation
Remove unneeded accounts from the Administrators group using:
> net localgroup administrators [AccountName] /del

