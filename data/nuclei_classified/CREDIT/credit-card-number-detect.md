# Vulnerability: Credit and Debit Card Number - Detection
**Classification:** CREDIT
**Source:** Nuclei Template (`credit-card-number-detect.yaml`)

## Description
This template is designed to identify the presence of credit or debit card numbers exposed within web pages, APIs, or other application responses. It searches for patterns matching card numbers using regular expressions aligned with common card formats, including Visa, MasterCard, American Express, and Discover cards. Detecting exposed card information can help identify potential compliance issues with standards like PCI DSS and mitigate risks of data leaks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

