# Vulnerability: Shai Hulud 2.0 - Supply Chain Malware Detection
**Classification:** CWE-1357
**Source:** Nuclei Template (`shai-hulud-supply-chain.yaml`)

## Description
Detects compromised npm packages from the Shai Hulud 2.0 supply chain attack discovered in November 2025.
The attack affected over 25,000 malicious repositories across approximately 350 GitHub users, targeting major organizations
including Zapier, ENS Domains, PostHog, Postman, AsyncAPI, Voiceflow, and BrowserBase. The malware executes during the
preinstall phase and performs credential theft, cloud resource access (AWS, Azure, GCP), and GitHub persistence through
self-hosted runners named 'SHA1HULUD'. Malicious versions were published between November 21-23, 2025.

