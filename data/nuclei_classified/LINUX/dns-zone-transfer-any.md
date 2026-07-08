# Vulnerability: DNS Zone Transfer Allowed to Any Host
**Classification:** LINUX
**Source:** Nuclei Template (`dns-zone-transfer-any.yaml`)

## Description
DNS Zone Transfer configured with "allow-transfer { any; };" allowed unrestricted zone transfers.This exposed sensitive details like hostnames, network structure, and system data that attackers could use for reconnaissance and further attacks.

