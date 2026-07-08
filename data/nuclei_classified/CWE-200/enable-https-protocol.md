# Vulnerability: Pfsense Web Admin Management Portal HTTPS Not Set - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`enable-https-protocol.yaml`)

## Description
PfSense Web Admin Management Portal is recommended to be accessible using only HTTPS protocol. HTTP transmits all data, including passwords, in clear text over the network and provides no assurance of the identity of the hosts involved, making it possible for an attacker to obtain sensitive information, modify data, and/or execute unauthorized operations.

