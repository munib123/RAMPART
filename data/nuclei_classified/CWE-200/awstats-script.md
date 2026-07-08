# Vulnerability: AWStats Script Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`awstats-script.yaml`)

## Description
AWStats configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/awstats.pl
GET {{BaseURL}}/cgi-bin/awstats.pl
GET {{BaseURL}}/logs/awstats.pl
GET {{BaseURL}}/webstats/awstats.pl
GET {{BaseURL}}/awstats/awstats.pl
GET {{BaseURL}}/cgi-bin/awstats/awstats.pl
GET {{BaseURL}}/awstats/awstats.pl?config=
```

