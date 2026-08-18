# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 78_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `78_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 26-66 of the vulnerable file.

 */

require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formother.class.php';
require_once DOL_DOCUMENT_ROOT.'/adherents/class/adherent.class.php';
require_once DOL_DOCUMENT_ROOT.'/adherents/class/adherent_type.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/company.lib.php';

$langs->loadLangs(array("members","companies"));

$action=GETPOST('action','aZ09');
$massaction=GETPOST('massaction','alpha');
$show_files=GETPOST('show_files','int');
$confirm=GETPOST('confirm','alpha');
$toselect = GETPOST('toselect', 'array');

// Security check
$result=restrictedArea($user,'adherent');

$filter=GETPOST("filter",'alpha');
$statut=GETPOST("statut",'alpha');
$search=GETPOST("search",'alpha');
$search_ref=GETPOST("search_ref",'alpha');
$search_lastname=GETPOST("search_lastname",'alpha');
$search_firstname=GETPOST("search_firstname",'alpha');
$search_login=GETPOST("search_login",'alpha');
$search_address=GETPOST("search_address",'alpha');
$search_zip=GETPOST("search_zip",'alpha');
$search_town=GETPOST("search_town",'alpha');
$search_state=GETPOST("search_state",'alpha');
$search_country=GETPOST("search_country",'alpha');
$search_phone=GETPOST("search_phone",'alpha');
$search_phone_perso=GETPOST("search_phone_perso",'alpha');
$search_phone_mobile=GETPOST("search_phone_mobile",'alpha');
$search_type=GETPOST("search_type",'alpha');
$search_email=GETPOST("search_email",'alpha');
$search_categ = GETPOST("search_categ",'int');
$catid        = GETPOST("catid",'int');
$optioncss = GETPOST('optioncss','alpha');

$sall=trim((GETPOST('search_all', 'alphanohtml')!='')?GETPOST('search_all', 'alphanohtml'):GETPOST('sall', 'alphanohtml'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
 $result=restrictedArea($user,'adherent');
 
 $filter=GETPOST("filter",'alpha');
-$statut=GETPOST("statut",'alpha');
+$statut=GETPOST("statut",'intcomma');
 $search=GETPOST("search",'alpha');
 $search_ref=GETPOST("search_ref",'alpha');
 $search_lastname=GETPOST("search_lastname",'alpha');
```
