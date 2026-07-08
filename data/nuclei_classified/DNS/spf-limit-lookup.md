# Vulnerability: SPF record DNS lookup limit
**Classification:** DNS
**Source:** Nuclei Template (`spf-limit-lookup.yaml`)

## Description
SPF (Sender Policy Framework) records that exceed the 10 DNS lookup limit was detected. SPF records with more than 10 DNS-based mechanisms may cause SPF authentication failures, leading to potential email delivery issues and spoofing risks.

