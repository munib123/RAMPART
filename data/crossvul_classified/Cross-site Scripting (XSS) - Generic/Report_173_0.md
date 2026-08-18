# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 173_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `173_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-7 of the vulnerable file.

<?php
define('G_APP_NAME', 'Chevereto Free');
define('G_APP_VERSION', '1.0.12');
define('G_APP_GITHUB_OWNER', 'Chevereto');
define('G_APP_GITHUB_REPO', 'Chevereto-Free');
define('G_APP_GITHUB_REPO_URL', 'https://github.com/' . G_APP_GITHUB_OWNER . '/' . G_APP_GITHUB_REPO);
define('CHEVERETO_INSTALLER_DOWNLOAD_URL', 'https://chevereto.com/download/file/installer');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 <?php
 define('G_APP_NAME', 'Chevereto Free');
-define('G_APP_VERSION', '1.0.12');
+define('G_APP_VERSION', '1.0.13');
 define('G_APP_GITHUB_OWNER', 'Chevereto');
 define('G_APP_GITHUB_REPO', 'Chevereto-Free');
 define('G_APP_GITHUB_REPO_URL', 'https://github.com/' . G_APP_GITHUB_OWNER . '/' . G_APP_GITHUB_REPO);
```
