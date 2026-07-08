# Vulnerability: Yelp User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`yelp.yaml`)

## Description
Yelp user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.yelp.com/user_details?userid={{user}}
```

