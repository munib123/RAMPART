# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 684_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `684_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.

/**
 * \file		htdocs/accountancy/admin/journals_list.php
 * \ingroup		Advanced accountancy
 * \brief		Setup page to configure journals
 */
require '../../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formadmin.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formcompany.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/functions2.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/doleditor.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/accounting.lib.php';
require_once DOL_DOCUMENT_ROOT.'/accountancy/class/accountingjournal.class.php';

$langs->load("admin");
$langs->load("compta");
$langs->load("accountancy");

$action=GETPOST('action','alpha')?GETPOST('action','alpha'):'view';
$confirm=GETPOST('confirm','alpha');
$id=GETPOST('id','int');
$rowid=GETPOST('rowid','alpha');
$code=GETPOST('code','alpha');

// Security access
if (empty($user->rights->accounting->chartofaccount))
{
	accessforbidden();
}

$acts[0] = "activate";
$acts[1] = "disable";
$actl[0] = img_picto($langs->trans("Disabled"),'switch_off');
$actl[1] = img_picto($langs->trans("Activated"),'switch_on');

$listoffset=GETPOST('listoffset');
$listlimit=GETPOST('listlimit')>0?GETPOST('listlimit'):1000;
$active = 1;

$sortfield = GETPOST("sortfield",'alpha');
$sortorder = GETPOST("sortorder",'alpha');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
 
 $action=GETPOST('action','alpha')?GETPOST('action','alpha'):'view';
 $confirm=GETPOST('confirm','alpha');
-$id=GETPOST('id','int');
+$id=35;
 $rowid=GETPOST('rowid','alpha');
 $code=GETPOST('code','alpha');
 
@@ -400,24 +400,9 @@
 	$sql=$tabsql[$id];
 	$sql.= " WHERE a.entity = ".$conf->entity;
 
-	if ($sortfield)
-	{
-		// If sort order is "country", we use country_code instead
-		if ($sortfield == 'country') $sortfield='country_code';
-		$sql.= " ORDER BY ".$sortfield;
-		if ($sortorder)
-		{
-			$sql.=" ".strtoupper($sortorder);
-		}
-		$sql.=", ";
-		// Clear the required sort criteria for the tabsqlsort to be able to force it with selected value
-		$tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.' '.$sortorder.',/i','',$tabsqlsort[$id]);
-		$tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.',/i','',$tabsqlsort[$id]);
-	}
-	else {
-		$sql.=" ORDER BY ";
-	}
-	$sql.=$tabsqlsort[$id];
+	// If sort order is "country", we use country_code instead
+	if ($sortfield == 'country') $sortfield='country_code';
+	$sql.=$db->order($sortfield,$sortorder);
 	$sql.=$db->plimit($listlimit+1,$offset);
 
 	$fieldlist=explode(',',$tabfield[$id]);
```
