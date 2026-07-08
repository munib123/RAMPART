# Vulnerability: baserCMS Installation - Exposure
**Classification:** CWE-284
**Source:** Nuclei Template (`basercms-install.yaml`)

## Description
baserCMS installation panel was detected. This indicates an incomplete installation that could be exploited by unauthorized users to set up the CMS with attacker-controlled parameters.

## Secure Mitigation
Complete the installation process immediately or restrict access to the installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

