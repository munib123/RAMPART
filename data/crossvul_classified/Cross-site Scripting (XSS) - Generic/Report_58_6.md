# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 58_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `58_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-20 of the vulnerable file.

<?php

/**
 *
 *set users widgets
 *
 */

# include required scripts
require_once( dirname(__FILE__) . '/../../../functions/functions.php' );

# initialize required objects
$Database 	= new Database_PDO;
$Result		= new Result;
$User		= new User ($Database);

/* save widgets */
if (!$User->self_update_widgets ($_POST['widgets'])) 	{ $Result->show("danger", _('Error updating'),true); }
else 													{ $Result->show("success", _('Widgets updated'),true); }
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,9 @@
 $Result		= new Result;
 $User		= new User ($Database);
 
+# verify that user is logged in
+$User->check_user_session();
+
 /* save widgets */
 if (!$User->self_update_widgets ($_POST['widgets'])) 	{ $Result->show("danger", _('Error updating'),true); }
 else 													{ $Result->show("success", _('Widgets updated'),true); }
```
