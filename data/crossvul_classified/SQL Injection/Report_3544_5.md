# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3544_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3544_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 18-58 of the vulnerable file.

 */

/**
 *      \file       htdocs/user/index.php
 * 		\ingroup	core
 *      \brief      Page of users
 *      \version    $Id: index.php,v 1.51 2011/07/31 23:19:42 eldy Exp $
 */

require("../main.inc.php");

if (! $user->rights->user->user->lire && ! $user->admin) accessforbidden();

$langs->load("users");
$langs->load("companies");

// Security check (for external users)
$socid=0;
if ($user->societe_id > 0) $socid = $user->societe_id;

$sall=isset($_GET["sall"])?$_GET["sall"]:$_POST["sall"];

$sortfield = GETPOST("sortfield",'alpha');
$sortorder = GETPOST("sortorder",'alpha');
$page = GETPOST("page",'int');
if ($page == -1) { $page = 0; }
$offset = $conf->liste_limit * $page;
$pageprev = $page - 1;
$pagenext = $page + 1;
$limit = $conf->liste_limit;
if (! $sortfield) $sortfield="u.login";
if (! $sortorder) $sortorder="ASC";

$userstatic=new User($db);
$companystatic = new Societe($db);

/*
 * View
 */

llxHeader();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,7 @@
 $socid=0;
 if ($user->societe_id > 0) $socid = $user->societe_id;
 
-$sall=isset($_GET["sall"])?$_GET["sall"]:$_POST["sall"];
+$sall=GETPOST("sall");
 
 $sortfield = GETPOST("sortfield",'alpha');
 $sortorder = GETPOST("sortorder",'alpha');
@@ -50,6 +50,7 @@
 
 $userstatic=new User($db);
 $companystatic = new Societe($db);
+
 
 /*
  * View
@@ -73,9 +74,8 @@
 {
     $sql.= " AND (u.login like '%".$_POST["search_user"]."%' OR u.name like '%".$_POST["search_user"]."%' OR u.firstname like '%".$_POST["search_user"]."%')";
 }
-if ($sall) $sql.= " AND (u.login like '%".$sall."%' OR u.name like '%".$sall."%' OR u.firstname like '%".$sall."%' OR u.email like '%".$sall."%' OR u.note like '%".$sall."%')";
-if ($sortfield) $sql.=" ORDER BY $sortfield $sortorder";
-
+if ($sall) $sql.= " AND (u.login like '%".$db->escape($sall)."%' OR u.name like '%".$db->escape($sall)."%' OR u.firstname like '%".$db->escape($sall)."%' OR u.email like '%".$db->escape($sall)."%' OR u.note like '%".$db->escape($sall)."%')";
+$sql.=$db->order($sortfield,$sortorder);
 $result = $db->query($sql);
 if ($result)
 {
```
