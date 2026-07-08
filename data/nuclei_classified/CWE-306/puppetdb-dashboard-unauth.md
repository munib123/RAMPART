# Vulnerability: PuppetDB Dashboard - Unauthenticated Access
**Classification:** CWE-306
**Source:** Nuclei Template (`puppetdb-dashboard-unauth.yaml`)

## Description
PuppetDB dashboard and API endpoints were found accessible without authentication. PuppetDB stores infrastructure configuration data including node facts, catalogs, and reports. Unauthenticated access exposes sensitive infrastructure details such as hostnames, IP addresses, OS versions, installed packages, Puppet classes, and configuration parameters across the entire managed environment.

## Secure Mitigation
Restrict access to PuppetDB by configuring certificate-based authentication (mutual TLS) in the jetty.ini or webserver.conf. Use firewall rules to limit access to trusted Puppet infrastructure hosts only. Disable the dashboard in production or place it behind an authenticated reverse proxy.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pdb/dashboard/index.html
GET {{BaseURL}}/dashboard/index.html
GET {{BaseURL}}/pdb/query/v4/facts
```

