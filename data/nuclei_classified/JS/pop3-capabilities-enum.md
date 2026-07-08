# Vulnerability: POP3 Capabilities - Enumeration
**Classification:** JS
**Source:** Nuclei Template (`pop3-capabilities-enum.yaml`)

## Description
POP3 capabilities are defined in RFC 2449. The CAPA command allows a client to ask a server what commands it supports and possibly any site-specific policy. Besides the list of supported commands, the IMPLEMENTATION string giving the server version may be available.

