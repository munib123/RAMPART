# Vulnerability: Oracle TNS Listener - Detect
**Classification:** JS
**Source:** Nuclei Template (`oracle-tns-listener.yaml`)

## Description
Oracle clients communicate with the database using the Transparent Network Substrate (TNS) protocol. When the listener receives a connection request (tcp port 1521, by default), it starts up a new database process and establishes a connection between the client and the database.

