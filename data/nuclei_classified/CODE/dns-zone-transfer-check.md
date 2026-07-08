# Vulnerability: DNS Zone Transfer Check
**Classification:** CODE
**Source:** Nuclei Template (`dns-zone-transfer-check.yaml`)

## Description
Ensure DNS zone transfers are restricted by verifying that the SecureSecondaries registry value is set to 2 for all active zones.
Unrestricted zone transfers can expose sensitive domain information, helping attackers map the network infrastructure.

## Secure Mitigation
Configure DNS zone transfer restrictions by:
- Disabling zone transfers entirely, or
- Restricting transfers to designated servers by setting the SecureSecondaries registry value to 2.

