# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2791_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2791_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 25-65 of the vulnerable file.

 */

require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/don/class/don.class.php';
if (! empty($conf->projet->enabled)) require_once DOL_DOCUMENT_ROOT.'/projet/class/project.class.php';

$langs->load("companies");
$langs->load("donations");

$sortfield = GETPOST("sortfield",'alpha');
$sortorder = GETPOST("sortorder",'alpha');
$page = GETPOST("page",'int');
$limit = GETPOST('limit')?GETPOST('limit','int'):$conf->liste_limit;
if (empty($page) || $page == -1) { $page = 0; }     // If $page is not defined, or '' or -1
$offset = $limit * $page;
$pageprev = $page - 1;
$pagenext = $page + 1;
if (! $sortorder) $sortorder="DESC";
if (! $sortfield) $sortfield="d.datedon";

$statut=isset($_GET["statut"])?$_GET["statut"]:"-1";
$search_all=GETPOST('sall', 'alphanohtml');
$search_ref=GETPOST('search_ref','alpha');
$search_company=GETPOST('search_company','alpha');
$search_name=GETPOST('search_name','alpha');
$search_amount = GETPOST('search_amount','alpha');
$optioncss = GETPOST('optioncss','alpha');

if (!$user->rights->don->lire) accessforbidden();

if (GETPOST('button_removefilter_x','alpha') || GETPOST('button_removefilter.x','alpha') || GETPOST('button_removefilter','alpha')) // Both test are required to be compatible with all browsers
{
	$search_all="";
    $search_ref="";
	$search_company="";
	$search_name="";
	$search_amount="";
}

// Initialize technical object to manage hooks of page. Note that conf->hooks_modules contains array of hook context
$hookmanager->initHooks(array('orderlist'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,7 @@
 if (! $sortorder) $sortorder="DESC";
 if (! $sortfield) $sortfield="d.datedon";
 
-$statut=isset($_GET["statut"])?$_GET["statut"]:"-1";
+$statut=(GETPOST("statut",'intcomma')!='')?GETPOST("statut",'intcomma'):"-1";
 $search_all=GETPOST('sall', 'alphanohtml');
 $search_ref=GETPOST('search_ref','alpha');
 $search_company=GETPOST('search_company','alpha');
@@ -90,13 +90,13 @@
 $sql.= " p.rowid as pid, p.ref, p.title, p.public";
 $sql.= " FROM ".MAIN_DB_PREFIX."don as d LEFT JOIN ".MAIN_DB_PREFIX."projet AS p";
 $sql.= " ON p.rowid = d.fk_projet WHERE 1 = 1";
-if ($statut >= 0)
-{
-	$sql .= " AND d.fk_statut = ".$statut;
+if ($statut != '' && $statut != '-1')
+{
+	$sql .= " AND d.fk_statut IN (".$statut.")";
 }
 if (trim($search_ref) != '')
 {
-    $sql.= ' AND d.rowid LIKE \'%'.$db->escape(trim($search_ref)) . '%\'';
+    $sql.= natural_search('d.ref',$search_ref);
 }
 if (trim($search_all) != '')
 {
@@ -110,7 +110,7 @@
 {
     $sql .= natural_search(array('d.lastname', 'd.firstname'), $search_name);
 }
-if ($search_amount) $sql.= natural_search(array('d.amount'), price2num(trim($search_amount)), 1);
+if ($search_amount) $sql.= natural_search('d.amount', $search_amount, 1);
 
 $sql.= $db->order($sortfield,$sortorder);
 $nbtotalofrecords = '';
@@ -131,17 +131,7 @@
     //if ($page > 0) $param.= '&page='.$page;
 	if ($optioncss != '') $param.='&optioncss='.$optioncss;
 
-	if ($statut >= 0)
-	{
-	    $donationstatic->statut=$statut;
-	    $label=$donationstatic->getLibStatut(0);
-		print_barre_liste($langs->trans("Donations"), $page, $_SERVER["PHP_SELF"], $param, $sortfield, $sortorder, '', $num,$nbtotalofrecords);
-	}
-	else
-	{
-		print_barre_liste($langs->trans("Donations"), $page, $_SERVER["PHP_SELF"], $param, $sortfield, $sortorder, '', $num,$nbtotalofrecords);
-	}
-
+	print_barre_liste($langs->trans("Donations"), $page, $_SERVER["PHP_SELF"], $param, $sortfield, $sortorder, '', $num,$nbtotalofrecords);
 
     print '<form method="get" action="'.$_SERVER["PHP_SELF"].'">'."\n";
     if ($optioncss != '') print '<input type="hidden" name="optioncss" value="'.$optioncss.'">';
```
