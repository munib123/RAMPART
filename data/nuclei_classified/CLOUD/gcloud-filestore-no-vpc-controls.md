# Vulnerability: Filestore Instance Not Protected by VPC Service Controls
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-filestore-no-vpc-controls.yaml`)

## Description
Ensure that VPC Service Controls are used to configure a security perimeter around your Google Cloud Filestore instances. VPC Service Controls is a powerful security tool that allows you to restrict access to your cloud resources, including Filestore instances, to specific networks and clients. This helps prevent data exfiltration and enhances the security posture of your cloud environment.

## Secure Mitigation
Configure VPC Service Controls perimeter to protect your Filestore instances by including the Cloud Filestore API (file.googleapis.com) in the restricted services list and adding your project to the perimeter's protected resources.

