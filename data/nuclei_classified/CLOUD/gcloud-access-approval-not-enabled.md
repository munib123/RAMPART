# Vulnerability: Access Approval Not Enabled in GCP Projects
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-access-approval-not-enabled.yaml`)

## Description
Ensure that Access Approval is enabled within your Google Cloud Platform (GCP) account to allow your explicit approval whenever Google personnel need to access your GCP projects. Once enabled, you can delegate users within your organization to approve access requests through IAM. Requests will show the requester's name/ID via email or Pub/Sub message for approval.

## Secure Mitigation
Enable Access Approval in your GCP projects to create a new control and logging layer that reveals who in your organization approved or denied access requests.

