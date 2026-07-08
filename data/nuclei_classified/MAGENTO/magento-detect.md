# Vulnerability: Magento Detect
**Classification:** MAGENTO
**Source:** Nuclei Template (`magento-detect.yaml`)

## Description
Identify Magento

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/graphql?query=+{customerDownloadableProducts+{+items+{+date+download_url}}+}
```

