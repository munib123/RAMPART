# Vulnerability: Yahoo! JAPAN Auction User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`yahoo-japan-auction.yaml`)

## Description
Yahoo! JAPAN Auction user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://auctions.yahoo.co.jp/follow/list/{{user}}
```

