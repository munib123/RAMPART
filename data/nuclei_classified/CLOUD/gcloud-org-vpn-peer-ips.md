# Vulnerability: VPN Peer IP Addresses Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-vpn-peer-ips.yaml`)

## Description
Ensure that only trusted IPv4 addresses can be configured as VPN peer IPs within your Google Cloud organization. By enforcing the "Restrict VPN Peer IPs" constraint policy, you can control the IP addresses that can be configured as VPN peer IPs within your Google Cloud organization in order to meet security and compliance requirements.

## Secure Mitigation
Configure the "Restrict VPN Peer IPs" policy at the organization level to explicitly specify which IPv4 addresses can be configured as VPN peer IPs. Use space-separated IP addresses in the policy configuration.

