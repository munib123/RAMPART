# Vulnerability: Public IP Access for Cloud SQL Instances Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-sql-public-ip.yaml`)

## Description
Ensure that "Restrict Public IP access on Cloud SQL instances" policy is enforced for your Google Cloud organizations. Due to strict security and compliance regulations, you can't allow GCP members to configure security-critical database instances with public IPs. For highly sensitive workloads, the access to the SQL database instances can be made only through private IP addresses or Google Cloud SQL Proxy.

## Secure Mitigation
Enable the "Restrict Public IP access on Cloud SQL instances" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the sql.restrictPublicIp constraint.

