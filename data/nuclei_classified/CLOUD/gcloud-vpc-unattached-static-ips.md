# Vulnerability: Unattached Static External IP Addresses
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vpc-unattached-static-ips.yaml`)

## Description
Identify and release any unattached (unused) static external IP addresses from your Google Cloud Platform (GCP) project in order to lower the cost of your cloud bill. A static external IP address is an IP address that is reserved for your GCP project until you decide to release it. Google Cloud considers a static external IP address as in use if it's associated with a virtual machine (VM) instance, whether the VM instance is running or stopped.

## Secure Mitigation
Release unused static external IP addresses using the 'gcloud compute addresses delete' command with the appropriate region and address name parameters. Example: gcloud compute addresses delete ADDRESS_NAME --region=REGION --project=PROJECT_ID

