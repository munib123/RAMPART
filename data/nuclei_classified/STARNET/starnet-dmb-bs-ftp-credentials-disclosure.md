# Vulnerability: StarNet DMB-BS - FTP Credentials Disclosure
**Classification:** STARNET
**Source:** Nuclei Template (`starnet-dmb-bs-ftp-credentials-disclosure.yaml`)

## Description
The StarNet Ruijie DMB-BS LED Display System contains a security vulnerability in its taskexport interface that allows unauthorized access to FTP server credentials and connection parameters. This exposure enables potential attackers to gain unauthorized access to the FTP server, potentially compromising the integrity and content of the LED display system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{RootURL}}/dmb/out/taskexport.jsp?taskcode
```

