# Vulnerability: LimeSurvey - Open Redirect via editorLink
**Classification:** CWE-601
**Source:** Nuclei Template (`limesurvey-open-redirect.yaml`)

## Description
LimeSurvey before 6.16.11 contains an open redirect vulnerability in the editorLink route. An attacker can craft a URL that redirects users to an arbitrary external site, potentially enabling phishing attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?r=editorLink&url=http://interact.sh/
```

