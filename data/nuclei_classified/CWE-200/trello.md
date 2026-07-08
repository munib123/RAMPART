# Vulnerability: Trello User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`trello.yaml`)

## Description
Trello user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://trello.com/1/Members/{{user}}?fields=activityBlocked%2CavatarUrl%2Cbio%2CbioData%2Cconfirmed%2CfullName%2CidEnterprise%2CidMemberReferrer%2Cinitials%2CmemberType%2CnonPublic%2Cproducts%2Curl%2Cusername
```

