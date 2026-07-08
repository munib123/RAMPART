# Vulnerability: DNSSEC Not Enabled for Google Cloud DNS Zones
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-dns-dnssec-unenabled.yaml`)

## Description
Ensure that DNSSEC security feature is enabled for all your Google Cloud DNS managed zones in order to protect your domains against spoofing and cache poisoning attacks. By default, DNSSEC is not enabled for Google Cloud public DNS managed zones.

## Secure Mitigation
Enable DNSSEC for each Google Cloud DNS managed zone through the Google Cloud Console or using the `gcloud dns managed-zones update` command with the `--dnssec-state=on` flag.

