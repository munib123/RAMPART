# Vulnerability: Wattpad User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wattpad.yaml`)

## Description
Wattpad user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.wattpad.com/api/v3/users/{{user}}?fields=username%2Cname%2Cdescription%2Cavatar%2CbackgroundUrl%2CcreateDate%2Clocation%2Cfollowing%2CfollowingRequest%2CnumFollowing%2Cfollower%2CfollowerRequest%2CnumFollowers%2CnumLists%2CnumStoriesPublished%2CvotesReceived%2Cfacebook%2Ctwitter%2Cwebsite%2Csmashwords%2Chighlight_colour%2Chtml_enabled%2Cverified%2Cambassador%2Cwattpad_squad%2Cis_staff%2Cprograms(wattpad_stars)%2CisPrivate%2CisMuted%2CexternalId%2Cnotes
```

