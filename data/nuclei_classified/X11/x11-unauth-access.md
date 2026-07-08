# Vulnerability: x11 - Unauthenticated Access
**Classification:** X11
**Source:** Nuclei Template (`x11-unauth-access.yaml`)

## Description
To check if you can connect to a remote X server, send an X11 initial connection request to TCP port 6000+n (where n is the display number). The response success byte (0x00 or 0x01) indicates if you are allowed; if successful, the script will display "X server access is granted," confirming that an attacker can connect to the X server

