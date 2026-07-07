# HackerOne Report: apps.owncloud.com: Malicious file upload leads to remote code execution
**Report ID:** 84374
**Vulnerability Class:** Code Injection

## Vulnerability Information & PoC
Hello ownCloud Security Team,

i am here to report a critical security vulnerability .

Proof of concept :

https://apps.owncloud.com/CONTENT/content-pre1/171172-1.php5

code source of uploaded file : 
<?php

phpinfo();

?>


## Discussion & Remediation Timeline
