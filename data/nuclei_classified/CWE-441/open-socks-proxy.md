# Vulnerability: Open SOCKS4/SOCKS5 proxy
**Classification:** CWE-441
**Source:** Nuclei Template (`open-socks-proxy.yaml`)

## Description
The host accepts unauthenticated SOCKS4/SOCKS5 connections and can proxy TCP traffic to external destinations. This could allow abuse for anonymization, spam, scanning, or network pivoting. Verification was performed by successfully connecting to 1.1.1.1:80 through the proxy.

