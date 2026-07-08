# Vulnerability: Exposed Magento 2 API
**Classification:** MAGENTO
**Source:** Nuclei Template (`magento-2-exposed-api.yaml`)

## Description
The API in Magento 2 can be accessed by the world without providing credentials. Through the API information like storefront, (hidden) products including prices are exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/rest/V1/products
GET {{BaseURL}}/rest/V1/store/storeConfigs
GET {{BaseURL}}/rest/V1/store/storeViews
```

