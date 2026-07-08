# Vulnerability: Minimize the Use of Primitive Roles
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-iam-primitive-roles.yaml`)

## Description
For production and security-critical cloud environments, limit the use of primitive roles such as "Owner", "Editor", and "Viewer" for Cloud IAM members. Instead, grant predefined roles to these IAM members to allow the least-permissive access required to perform their tasks (i.e., Principle of Least Privilege – POLP).

## Secure Mitigation
Replace primitive roles with predefined or custom roles tailored to the specific needs of the users and the minimum permissions they require to perform their tasks.

