# HackerOne Report: Insecure Local Data Storage  : Application stores data using a binary sqlite database
**Report ID:** 57918
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Android provides several options for developers to save persistent application data. The local DB should store data depending on whether the data should be private to your application or accessible to other applications and users. In any case, sensible data always have to be encrypted to avoid privacy violation. Linkedin App keeps user data  in  a  SQLite  database

 w.db

OWASP:  Insecure Storage

OWASP:  Insecure Data Storage


## Discussion & Remediation Timeline
