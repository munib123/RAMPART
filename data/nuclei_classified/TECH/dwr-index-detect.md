# Vulnerability: DWR detect test page detection
**Classification:** TECH
**Source:** Nuclei Template (`dwr-index-detect.yaml`)

## Description
The index contains the list of exposed Java classes. From here one can navigate to the test page of each class where every callable method is described and can be easily tested. This is a great way to find out what methods are exposed and learn how they function.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dwr/index.html
```

