# Vulnerability: Azure SQL Managed Instance TLS Version Not Latest
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-sql-mi-tls-version-outdated.yaml`)

## Description
Ensure that your Microsoft Azure SQL managed instances are using the latest supported version of the TLS protocol (i.e. TLS 1.2) for inbound connections in order to enhance security by providing stronger encryption, protecting data integrity, reducing vulnerabilities to cyber attacks, and maintaining compatibility with modern browsers.

## Secure Mitigation
Update the TLS configuration of your Azure SQL managed instances to use TLS 1.2, ensuring enhanced security and compliance with industry best practices.

