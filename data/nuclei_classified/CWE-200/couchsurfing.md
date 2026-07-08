# Vulnerability: Couchsurfing User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`couchsurfing.yaml`)

## Description
Couchsurfing user name information check was conducted. This OSINT template looks for information about a user name in Couchsurfing.CouchSurfing is a hospitality exchange service by which users can request free short-term homestays or interact with other people who are interested in travel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.couchsurfing.com/people/{{user}}
```

