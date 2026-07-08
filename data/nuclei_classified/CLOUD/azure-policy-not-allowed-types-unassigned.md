# Vulnerability: Azure Policy - Not Allowed Resource Types Policy Assignment Not in Use
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-policy-not-allowed-types-unassigned.yaml`)

## Description
Ensure that a "Not Allowed Resource Types" policy is assigned to your Azure subscriptions in order to deny deploying restricted resources within your Azure cloud account for security and compliance purposes. Microsoft Azure Policy service allows you to enforce organizational standards and assess cloud compliance at-scale. The "Not Allowed Resource Types" policy assignment must use the built-in policy definition which enables you to specify the cloud resource types that your organization cannot deploy.

## Secure Mitigation
Assign the "Not Allowed Resource Types" policy to your Azure subscriptions to ensure compliance with corporate standards and prevent unauthorized resource deployment.

