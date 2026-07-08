# Vulnerability: Cloud Asset Inventory Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-os-config-disabled.yaml`)

## Description
Ensure that Cloud Asset Inventory is enabled for all your GCP projects in order to efficiently manage the history and the inventory of your cloud resources. Google Cloud Asset Inventory is a fully managed metadata inventory service that allows you to view, monitor, analyze, and gain insights for your Google Cloud and Anthos assets. Cloud Asset Inventory is disabled by default in each GCP project.

## Secure Mitigation
Enable the Google Cloud Asset Inventory by activating the Cloud Asset API in each GCP project through the Google Cloud Console or using the `gcloud services enable cloudasset.googleapis.com --project <project-id>` command.

