# Vulnerability: OpenVPN Host Header Injection
**Classification:** OPENVPN
**Source:** Nuclei Template (`openvpn-hhi.yaml`)

## Description
A vulnerability in OpenVPN Access Server allows remote attackers to inject arbitrary redirection URLs by using the 'Host' HTTP header field.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

