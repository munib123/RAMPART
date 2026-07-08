# Vulnerability: Disk Images Publicly Shared
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-disk-image-public-access.yaml`)

## Description
Ensure that your virtual machine disk images are not publicly shared with all other Google Cloud Platform (GCP) accounts in order to avoid exposing sensitive or confidential data. If required, you can share your disk images with specific GCP accounts only, without making them public.

## Secure Mitigation
Remove the "allAuthenticatedUsers" member from the IAM policy of affected disk images using the 'gcloud compute images remove-iam-policy-binding' command or through the Google Cloud Console.

