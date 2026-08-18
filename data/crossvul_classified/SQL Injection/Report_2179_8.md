# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 35-75 of the vulnerable file.

 * SVN : $Id$
 *
 */

    if (!isset($_GET['id'])) {
        exit;
    }

    $nextRowId = htmlentities($_GET['id'], ENT_QUOTES, "UTF-8") + 1;
    $nbOfInitialRows = htmlentities($_GET['nbOfInitialRows'], ENT_QUOTES, "UTF-8");
    $currentId = htmlentities($_GET['id'], ENT_QUOTES, "UTF-8");

    include_once("@CENTREON_ETC@/centreon.conf.php");
	require_once $centreon_path . "/www/class/centreonXML.class.php";

        /*
	 * Get session
	 */
	require_once ($centreon_path . "www/class/centreonSession.class.php");
	require_once ($centreon_path . "www/class/centreon.class.php");
	if(!isset($_SESSION['centreon'])) {
		CentreonSession::start();
	}

	if (isset($_SESSION['centreon'])) {
            $oreon = $_SESSION['centreon'];
	} else {
            exit;
	}

	/*
	 * Get language
	 */
	$locale = $oreon->user->get_lang();
	putenv("LANG=$locale");
	setlocale(LC_ALL, $locale);
	bindtextdomain("messages",  $centreon_path . "www/locale/");;
	bind_textdomain_codeset("messages", "UTF-8");
	textdomain("messages");
        
    /*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
 	 */
 	require_once ($centreon_path . "www/class/centreonSession.class.php");
 	require_once ($centreon_path . "www/class/centreon.class.php");
-	if(!isset($_SESSION['centreon'])) {
+	if (!isset($_SESSION['centreon'])) {
 		CentreonSession::start();
 	}
 
```
