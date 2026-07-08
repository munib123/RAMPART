# Vulnerability: Enable Self-Service Password Change for IAM Users
**Classification:** CLOUD
**Source:** Nuclei Template (`iam-user-password-change.yaml`)

## Description
Verifies that all Amazon IAM users have permissions to change their own console passwords, allowing access to 'iam:ChangePassword' for their accounts and 'iam:GetAccountPasswordPolicy' action.

