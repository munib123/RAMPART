# Vulnerability: IAM Users with Administrative Roles
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-iam-admin-roles.yaml`)

## Description
Ensure that IAM roles with privileged administrative permissions are not assigned to IAM identities (users, groups, and service accounts) to promote least privilege and provide your members (principals) the minimal access required to perform their tasks. When IAM members have administrator privileges (Owner and Editor roles, or roles containing "Admin" or "admin" in their names), they can access, create, and manage cloud resources.

## Secure Mitigation
Remove administrative roles (Owner, Editor, and roles containing "Admin" or "admin") from IAM members and replace them with more granular roles that follow the principle of least privilege.

