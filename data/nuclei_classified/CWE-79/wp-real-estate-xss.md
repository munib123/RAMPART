# Vulnerability: WordPress Real Estate 7 Theme <= 3.3.4 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-real-estate-xss.yaml`)

## Description
The Real Estate 7 premium theme for WordPress is vulnerable to Reflected Cross-Site Scripting (XSS) attack vector in versions up to, and including, v3.3.4 via the 'ct_additional_features' option due to insufficient input sanitization and output escaping. This vulnerability allows unauthenticated attackers to inject malicious JavaScript payload in the search page that execute if they can trick a user into performing an action such as clicking on a link.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?ct_keyword=%22%3E%3Cimg%20src%3Dx%20onerror%3Dprompt%28document.domain%29%3E&ct_city=0&ct_state=0&ct_zipcode=0&search-listings=true&ct_property_type=0&ct_beds=0&ct_baths=0&ct_price_from&ct_price_to
```

