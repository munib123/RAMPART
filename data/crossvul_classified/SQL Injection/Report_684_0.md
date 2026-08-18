# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 684_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `684_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 28-68 of the vulnerable file.


/**
 *	    \file       htdocs/accountancy/admin/accountmodel.php
 *		\ingroup    Advanced accountancy
 *		\brief      Page to administer model of chart of accounts
 */

require '../../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formadmin.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formcompany.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/functions2.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/doleditor.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/accounting.lib.php';
if (! empty($conf->accounting->enabled)) require_once DOL_DOCUMENT_ROOT . '/core/class/html.formaccounting.class.php';

$langs->loadLangs(array("errors","admin","companies","resource","holiday","compta","accountancy","hrm"));

$action=GETPOST('action','alpha')?GETPOST('action','alpha'):'view';
$confirm=GETPOST('confirm','alpha');
$id=GETPOST('id','int');
$rowid=GETPOST('rowid','alpha');
$code=GETPOST('code','alpha');

$acts[0] = "activate";
$acts[1] = "disable";
$actl[0] = img_picto($langs->trans("Disabled"),'switch_off');
$actl[1] = img_picto($langs->trans("Activated"),'switch_on');

$listoffset=GETPOST('listoffset');
$listlimit=GETPOST('listlimit')>0?GETPOST('listlimit'):1000;
$active = 1;

$sortfield = GETPOST("sortfield",'alpha');
$sortorder = GETPOST("sortorder",'alpha');
$page = GETPOST("page",'int');
if (empty($page) || $page == -1) { $page = 0; }     // If $page is not defined, or '' or -1
$offset = $listlimit * $page ;
$pageprev = $page - 1;
$pagenext = $page + 1;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,7 +45,7 @@
 
 $action=GETPOST('action','alpha')?GETPOST('action','alpha'):'view';
 $confirm=GETPOST('confirm','alpha');
-$id=GETPOST('id','int');
+$id=31;
 $rowid=GETPOST('rowid','alpha');
 $code=GETPOST('code','alpha');
 
@@ -58,8 +58,8 @@
 $listlimit=GETPOST('listlimit')>0?GETPOST('listlimit'):1000;
 $active = 1;
 
-$sortfield = GETPOST("sortfield",'alpha');
-$sortorder = GETPOST("sortorder",'alpha');
+$sortfield = GETPOST("sortfield",'aZ09comma');
+$sortorder = GETPOST("sortorder",'aZ09comma');
 $page = GETPOST("page",'int');
 if (empty($page) || $page == -1) { $page = 0; }     // If $page is not defined, or '' or -1
 $offset = $listlimit * $page ;
@@ -84,59 +84,48 @@
 $tabname=array();
 
 $tabname[31]= MAIN_DB_PREFIX."accounting_system";
-$tabname[32]= MAIN_DB_PREFIX."c_accounting_category";
 
 // Dictionary labels
 $tablib=array();
 $tablib[31]= "Pcg_version";
-$tablib[32]= "DictionaryAccountancyCategory";
 
 // Requests to extract data
 $tabsql=array();
 $tabsql[31]= "SELECT s.rowid as rowid, pcg_version, s.label, s.fk_country as country_id, c.code as country_code, c.label as country, s.active FROM ".MAIN_DB_PREFIX."accounting_system as s, ".MAIN_DB_PREFIX."c_country as c WHERE s.fk_country=c.rowid and c.active=1";
-$tabsql[32]= "SELECT a.rowid as rowid, a.code as code, a.label, a.range_account, a.sens, a.category_type, a.formula, a.position as position, a.fk_country as country_id, c.code as country_code, c.label as country, a.active FROM ".MAIN_DB_PREFIX."c_accounting_category as a, ".MAIN_DB_PREFIX."c_country as c WHERE a.fk_country=c.rowid and c.active=1";
 
 // Criteria to sort dictionaries
 $tabsqlsort=array();
 $tabsqlsort[31]="pcg_version ASC";
-$tabsqlsort[32]="position ASC";
 
 // Nom des champs en resultat de select pour affichage du dictionnaire
 $tabfield=array();
 $tabfield[31]= "pcg_version,label,country_id,country";
-$tabfield[32]= "code,label,range_account,sens,category_type,formula,position,country_id,country";
 
 // Nom des champs d'edition pour modification d'un enregistrement
 $tabfieldvalue=array();
 $tabfieldvalue[31]= "pcg_version,label,country";
-$tabfieldvalue[32]= "code,label,range_account,sens,category_type,formula,position,country";
 
 // Nom des champs dans la table pour insertion d'un enregistrement
 $tabfieldinsert=array();
 $tabfieldinsert[31]= "pcg_version,label,fk_country";
-$tabfieldinsert[32]= "code,label,range_account,sens,category_type,formula,position,fk_country";
 
 // Nom du rowid si le champ n'est pas de type autoincrement
 // Example: "" if id field is "rowid" and has autoincrement on
 //          "nameoffield" if id field is not "rowid" or has not autoincrement on
 $tabrowid=array();
 $tabrowid[31]= "";
-$tabrowid[32]= "";
 
 // Condition to show dictionary in setup page
 $tabcond=array();
 $tabcond[31]= ! empty($conf->accounting->enabled);
-$tabcond[32]= ! empty($conf->accounting->enabled);
 
 // List of help for fields
 $tabhelp=array();
 $tabhelp[31] = array('pcg_version'=>$langs->trans("EnterAnyCode"));
-$tabhelp[32] = array('code'=>$langs->trans("EnterAnyCode"));
 
 // List of check for fields (NOT USED YET)
 $tabfieldcheck=array();
 $tabfieldcheck[31] = array();
-$tabfieldcheck[32] = array();
 
 
 // Define elementList and sourceList (used for dictionary type of contacts "llx_c_type_contact")
@@ -484,7 +473,7 @@
 // Confirmation de la suppression de la ligne
 if ($action == 'delete')
 {
-	print $form->formconfirm($_SERVER["PHP_SELF"].'?'.($page?'page='.$page.'&':'').'sortfield='.$sortfield.'&sortorder='.$sortorder.'&rowid='.$rowid.'&code='.$code.'&id='.$id, $langs->trans('DeleteLine'), $langs->trans('ConfirmDeleteLine'), 'confirm_delete','',0,1);
+	print $form->formconfirm($_SERVER["PHP_SELF"].'?'.($page?'page='.urlencode($page).'&':'').'sortfield='.urlencode($sortfield).'&sortorder='.urlencode($sortorder).'&rowid='.urlencode($rowid).'&code='.urlencode($code).'&id='.urlencode($id), $langs->trans('DeleteLine'), $langs->trans('ConfirmDeleteLine'), 'confirm_delete','',0,1);
 }
 //var_dump($elementList);
 
@@ -503,24 +492,9 @@
 		$sql.= " c.rowid = ".$search_country_id;
 	}
 
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
 	//print $sql;
 
```
