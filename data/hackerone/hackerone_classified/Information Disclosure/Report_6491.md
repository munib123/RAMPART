# HackerOne Report: c2fo.com is releasing sensitive Information about Database Configuration.
**Report ID:** 6491
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hello C2FO Securiity Team,

Vulnerability Details : Disclosure of Database Username and Password of c2fo.com

Description: Your configuration file of your website is available to download from your website c2fo.com.When i thought to pentest your site,i landed on https://c2fo.com .But instead of showing the website it showed 403 Forbidden error.It seemed weird to me ,then i went to the link https://c2fo.com/wp-config.php and the file downloaded to my computer.Then i tried to download .htaccess and wp-login.php and yes they were also available to download.

POC:

I have made proof of concept video of the same :- https://www.youtube.com/watch?v=AXq-YWO_EhI
The above video is unlisted .

Below is some lines from wp-config.php

# Database Configuration
define('DB_NAME','wp_c2fo');
define('DB_USER','c2fo');
define('DB_PASSWORD','*********');
define('DB_HOST','127.0.0.1');
define('DB_HOST_SLAVE','127.0.0.1');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', 'utf8_unicode_ci');
$table_prefix = 'wp_';

I have included all the files i have downloaded ,in the attachment .

Remedy:- Please change your configuration file as soon as possible because might be some attacker have also downloaded the file and use it for future attack's on c2fo.com

With regard's

Aditya Agrawal


## Discussion & Remediation Timeline
