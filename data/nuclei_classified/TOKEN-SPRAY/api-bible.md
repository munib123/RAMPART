# Vulnerability: API.Bible API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-bible.yaml`)

## Description
Everything you need from the Bible in one discoverable place

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.scripture.api.bible/v1/bibles/a6aee10bb058511c-02/verses/JHN.3.16?fums-version=3
```

