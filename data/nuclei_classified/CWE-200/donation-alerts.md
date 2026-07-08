# Vulnerability: Donation Alerts User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`donation-alerts.yaml`)

## Description
Donation Alerts user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.donationalerts.com/api/v1/user/{{user}}/donationpagesettings
```

