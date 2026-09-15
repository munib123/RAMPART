# Nuclei Template: PuppetDB Dashboard - Unauthenticated Access
**Template ID:** puppetdb-dashboard-unauth
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`puppetdb-dashboard-unauth.yaml`)

## Vulnerability Information & PoC

## Description
PuppetDB dashboard and API endpoints were found accessible without authentication. PuppetDB stores infrastructure configuration data including node facts, catalogs, and reports. Unauthenticated access exposes sensitive infrastructure details such as hostnames, IP addresses, OS versions, installed packages, Puppet classes, and configuration parameters across the entire managed environment.

## Impact
An attacker can enumerate the entire Puppet-managed infrastructure, extract node facts (hostnames, IPs, OS details, hardware specs), read catalogs containing configuration secrets, and gather intelligence for lateral movement or targeted attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/pdb/dashboard/index.html
GET {{BaseURL}}/dashboard/index.html
GET {{BaseURL}}/pdb/query/v4/facts
```

## Remediation
Restrict access to PuppetDB by configuring certificate-based authentication (mutual TLS) in the jetty.ini or webserver.conf. Use firewall rules to limit access to trusted Puppet infrastructure hosts only. Disable the dashboard in production or place it behind an authenticated reverse proxy.

## References
- https://puppet.com/docs/puppetdb/latest/configure.html
- https://puppet.com/docs/puppetdb/latest/api/index.html
- https://puppet.com/security/cve/CVE-2020-7943
