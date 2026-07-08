# Vulnerability: DNS Zone Transfer Check (AXFR)
**Classification:** DNS
**Source:** Nuclei Template (`dns-axfr-enabled.yaml`)

## Description
Checks if particular domain can be queried via DNS Zone Transfer (AXFR). An open zone transfer can disclose all DNS records for a zone, leading to information leakage.

