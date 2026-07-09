# Nuclei Template: Lantronix XPort 6.10.0.1 - Unauthenticated Access
**Template ID:** lantronix-xport-unauth
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`lantronix-xport-unauth.yaml`)

## Vulnerability Information & PoC

## Description
The Lantronix XPort's telnet service is not configured to require authentication by default.An unauthenticated user can remotely administer the device by hitting 'Enter' when prompted by the telnet service.

## References
- https://www.lantronix.com/wp-content/uploads/pdf/XPort_UG.pdf
