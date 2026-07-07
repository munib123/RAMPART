# HackerOne Report: PHP PDOException and Full Path Disclosure
**Report ID:** 19363
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
hi
phrasekey , agian!

in phraseChange action if set to array pdo quote show error!
line 755 index.php

Warning: PDO::quote() expects parameter 1 to be string, array given in /srv/data/web/vhosts/www.localize.im/htdocs/classes/Database.php on line 30

Fatal error: Uncaught exception 'PDOException' with message 'SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1' in /srv/data/web/vhosts/www.localize.im/htdocs/classes/Database.php:57 Stack trace: #0 /srv/data/web/vhosts/www.localize.im/htdocs/classes/Database.php(57): PDO->exec('DELETE FROM phr...') #1 /srv/data/web/vhosts/www.localize.im/htdocs/classes/Database.php(325): Database::delete('DELETE FROM phr...') #2 /srv/data/web/vhosts/www.localize.im/htdocs/index.php(768): Database::phraseDelete(340, Array) #3 {main} thrown in /srv/data/web/vhosts/www.localize.im/htdocs/classes/Database.php on line 57

## Discussion & Remediation Timeline
