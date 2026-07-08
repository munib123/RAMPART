# Vulnerability: Unrestricted SMTP Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-smtp-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access on TCP port 25, used for Simple Mail Transfer Protocol (SMTP), to prevent spam and unauthorized email relay.

## Secure Mitigation
Configure NSG rules to restrict access to SMTP services on TCP port 25. Allow only trusted IP addresses to send emails and implement proper email authentication mechanisms.

