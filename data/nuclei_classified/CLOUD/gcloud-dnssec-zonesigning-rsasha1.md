# Vulnerability: DNSSEC RSASHA1 Algorithm Deprecated
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-dnssec-zonesigning-rsasha1.yaml`)

## Description
Ensure that Domain Name System Security Extensions (DNSSEC) feature is not using the deprecated RSASHA1 algorithm for the Zone-Signing Key (ZSK) associated with your public DNS managed zone.

## Secure Mitigation
Update the DNSSEC configuration to use a stronger, more secure signing algorithm like RSASHA256 or ECDSAP256SHA256 for your DNS managed zones.

