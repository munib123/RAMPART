# Vulnerability: Lantronix XPort 6.10.0.1 - Unauthenticated Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`lantronix-xport-unauth.yaml`)

## Description
The Lantronix XPort's telnet service is not configured to require authentication by default.An unauthenticated user can remotely administer the device by hitting 'Enter' when prompted by the telnet service.

