# Vulnerability: Trusted Image Projects Not Defined
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-trusted-images.yaml`)

## Description
Ensure that only images from trusted Google Cloud Platform (GCP) projects are allowed as the source for boot disks for new virtual machine instances. By enforcing the "Define Trusted Image Projects" policy at the GCP organization level, you can restrict access to disk images so that project members can create boot disks only from images that contain approved software meeting strict security requirements.

## Secure Mitigation
Configure the "Define Trusted Image Projects" policy at the organization level to explicitly specify trusted projects. Use the format projects/<project-id> where <project-id> is the ID of the trusted Google Cloud project that shares approved disk images.

