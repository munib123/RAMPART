# Nuclei Template: Shai Hulud 2.0 - Supply Chain Malware Detection
**Template ID:** shai-hulud-supply-chain
**Vulnerability Class:** Using Components with Known Vulnerabilities
**Severity:** Critical
**CWE:** CWE-1357
**Source:** Nuclei Template (`shai-hulud-supply-chain.yaml`)

## Vulnerability Information & PoC

## Description
Detects compromised npm packages from the Shai Hulud 2.0 supply chain attack discovered in November 2025.
The attack affected over 25,000 malicious repositories across approximately 350 GitHub users, targeting major organizations
including Zapier, ENS Domains, PostHog, Postman, AsyncAPI, Voiceflow, and BrowserBase. The malware executes during the
preinstall phase and performs credential theft, cloud resource access (AWS, Azure, GCP), and GitHub persistence through
self-hosted runners named 'SHA1HULUD'. Malicious versions were published between November 21-23, 2025.

## References
- https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
- https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains
