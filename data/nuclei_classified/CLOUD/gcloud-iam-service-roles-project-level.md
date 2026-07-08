# Vulnerability: Service Account Roles at Project Level
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-iam-service-roles-project-level.yaml`)

## Description
Ensure that the Service Account User and Service Account Token Creator roles are assigned to a user for a specific GCP service account rather than to a user at the GCP project level, in order to implement the principle of least privilege (POLP). The principle of least privilege (also known as the principle of minimal privilege) is the practice of providing every user the minimal amount of access required to perform its tasks. The Service Account User (iam.serviceAccountUser) role allows an IAM user to attach a service account to a long-running job service such as an App Engine App or Dataflow Job, whereas the Service Account Token Creator (iam.serviceAccountTokenCreator) role allows a user to directly impersonate the identity of a service account.

## Secure Mitigation
Ensure these roles are assigned directly to service accounts and not at the project level to enforce the principle of least privilege.

