# Vulnerability: Check Bucket Policies with Administrative Permissions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-bucket-policies-admin-permissions.yaml`)

## Description
Ensure that the IAM policy associated with your Google Cloud Storage buckets does not grant privileged, administrative permissions. This promotes the Principle of Least Privilege (POLP) by providing principals only the minimal access required to perform their tasks.

## Secure Mitigation
Review and update IAM policies for your Google Cloud Storage buckets to remove roles such as roles/owner, roles/editor, or any roles containing "Admin" to adhere to the Principle of Least Privilege.

