# Vulnerability: Secure donation User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`secure-donation.yaml`)

## Description
Secure donation user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://secure.donationpay.org/{{user}}/
```

