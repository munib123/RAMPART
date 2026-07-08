# Vulnerability: Typo3 composer.json Exposure
**Classification:** TYPO3
**Source:** Nuclei Template (`typo3-composer.yaml`)

## Description
The web application is based on Typo3 CMS. A sensitive file has been found. Access to such files must be restricted, as it may lead to disclosure of sensitive information about the web application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/typo3/sysext/install/composer.json
```

