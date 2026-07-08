# Vulnerability: Publicly Accessible BigQuery Datasets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-bigquery-public-datasets.yaml`)

## Description
Ensure there are no anonymously and/or publicly accessible BigQuery datasets available within your Google Cloud Platform (GCP) account. Google Cloud BigQuery datasets have Identity and Access Management (IAM) policies configured to determine who can have access to these resources. To refuse access from anonymous and public users, remove the bindings for "allUsers" and "allAuthenticatedUsers" members from the IAM policy associated with your datasets.

## Secure Mitigation
Update the IAM policies for each BigQuery dataset to remove "allUsers" and "allAuthenticatedUsers". This action will ensure that datasets are not exposed to any user on the internet or authenticated users not explicitly granted permission.

