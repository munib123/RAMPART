# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2990_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2990_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.

/**
 *      \file       htdocs/adherents/subscription/info.php
 *      \ingroup    member
 *      \brief      Page with information of subscriptions of a member
 */

require '../../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/functions2.lib.php';
require_once DOL_DOCUMENT_ROOT.'/adherents/class/adherent.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/member.lib.php';
require_once DOL_DOCUMENT_ROOT.'/adherents/class/subscription.class.php';

$langs->load("companies");
$langs->load("bills");
$langs->load("members");
$langs->load("users");

if (!$user->rights->adherent->lire)
	accessforbidden();

$rowid=isset($_GET["rowid"])?$_GET["rowid"]:$_POST["rowid"];



/*
 * View
 */

llxHeader();

$form = new Form($db);

$object = new Subscription($db);
$result = $object->fetch($rowid);

$head = subscription_prepare_head($object);

dol_fiche_head($head, 'info', $langs->trans("Subscription"), -1, 'payment');

$linkback = '<a href="'.DOL_URL_ROOT.'/adherents/subscription/list.php">'.$langs->trans("BackToList").'</a>';

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
 if (!$user->rights->adherent->lire)
 	accessforbidden();
 
-$rowid=isset($_GET["rowid"])?$_GET["rowid"]:$_POST["rowid"];
+$rowid=GETPOST("rowid",'int');
 
 
 
@@ -44,9 +44,9 @@
  * View
  */
 
+$form = new Form($db);
+
 llxHeader();
-
-$form = new Form($db);
 
 $object = new Subscription($db);
 $result = $object->fetch($rowid);
```
