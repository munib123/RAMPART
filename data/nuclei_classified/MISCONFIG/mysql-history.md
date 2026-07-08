# Vulnerability: Mysql History - File Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mysql-history.yaml`)

## Description
The mysql_history file is a history file used by the MySQL command-line client (mysql) to store a record of the SQL commands and statements entered by a user during their interactive MySQL sessions. It serves as a command history for the MySQL client, allowing users to recall and reuse previously executed SQL commands.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.mysql_history
```

