# Vulnerability: DNSSEC RSASHA1 Algorithm Deprecated Usage
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-dnssec-keysigning-rsasha1.yaml`)

## Description
Ensure that Domain Name System Security Extensions (DNSSEC) feature is not using the deprecated RSASHA1 algorithm for the Key-Signing Key (KSK) associated with your DNS managed zone file.

## Secure Mitigation
Update the DNSSEC configuration for each DNS managed zone to use more secure algorithms like RSASHA256 or ECDSAP256SHA256 for the Key-Signing Key (KSK).

