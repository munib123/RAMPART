# Vulnerability: Administrator Account Rename Check
**Classification:** ACCOUNT-MANAGEMENT
**Source:** Nuclei Template (`admin-account-rename.yaml`)

## Description
Ensure the default Administrator account has been renamed to help prevent targeted brute-force attacks.

## Secure Mitigation
Rename the Administrator account using Local Security Policy or the following command-line instruction:
> wmic UserAccount where Name="administrator" call Rename Name="NEW_NAME"

