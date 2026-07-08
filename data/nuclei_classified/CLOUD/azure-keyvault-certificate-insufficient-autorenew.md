# Vulnerability: Check for Sufficient Certificate Auto-Renewal Period
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-certificate-insufficient-autorenew.yaml`)

## Description
Ensure that your Microsoft Azure Key Vault SSL certificates have a sufficient auto-renewal period configured for security and compliance purposes. This period indicates the amount of time (number of days) before SSL certificate expiration, when the renewal process is automatically triggered.

## Secure Mitigation
Configure SSL certificates within Azure Key Vaults to have an auto-renewal period that aligns with your organization's security and compliance requirements to ensure timely and effective renewal.

