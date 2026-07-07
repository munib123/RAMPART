# HackerOne Report: FULL PATH DISCLOSUR 
**Report ID:** 7736
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Full Path Disclosure (FPD) vulnerabilities enable the attacker to see the path to the webroot/file. e.g.: /home/omg/htdocs/file/. Certain vulnerabilities, such as using the load_file() (within a SQL Injection) query to view the page source, require the attacker to have the full path to the file they wish to view. 

url: 
http://enterprise.concrete5.com/

How to fix this vulnerability
Review the source code for this script.

How to replicate:
Cookie input CONCRETE5 was set to 
Error message found: 
<b>Warning</b>:  session_start() [<a href='function.session-start'>function.session-start</a>]: The session id is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,' in <b>/home/enterpri/public_html/updates/concrete5.6.1.2_updater/concrete/startup/session.php</b> on line <b>36</b><br />

as we can see clearly the full path 

Affected params : 
/ 
/index.php 
/tools/required/captcha 


## Discussion & Remediation Timeline
