# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3391_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3391_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 102-142 of the vulnerable file.

);
// Extra fields
if (is_array($extrafields->attribute_label) && count($extrafields->attribute_label))
{
   foreach($extrafields->attribute_label as $key => $val)
   {
       $arrayfields["ef.".$key]=array('label'=>$extrafields->attribute_label[$key], 'checked'=>$extrafields->attribute_list[$key], 'position'=>$extrafields->attribute_pos[$key], 'enabled'=>$extrafields->attribute_perms[$key]);
   }
}

// Init search fields
$sall=GETPOST('sall', 'alphanohtml');
$search_user=GETPOST('search_user','alpha');
$search_login=GETPOST('search_login','alpha');
$search_lastname=GETPOST('search_lastname','alpha');
$search_firstname=GETPOST('search_firstname','alpha');
$search_gender=GETPOST('search_gender','alpha');
$search_employee=GETPOST('search_employee','alpha');
$search_accountancy_code=GETPOST('search_accountancy_code','alpha');
$search_email=GETPOST('search_email','alpha');
$search_statut=GETPOST('search_statut','alpha');
$search_thirdparty=GETPOST('search_thirdparty','alpha');
$search_supervisor=GETPOST('search_supervisor','alpha');
$search_previousconn=GETPOST('search_previousconn','alpha');
$optioncss = GETPOST('optioncss','alpha');

// Default search
if ($search_statut == '') $search_statut='1';
if ($mode == 'employee') $search_employee=1;



/*
 * Actions
 */

if (GETPOST('cancel')) { $action='list'; $massaction=''; }
if (! GETPOST('confirmmassaction') && $massaction != 'presend' && $massaction != 'confirm_presend' && $massaction != 'confirm_createbills') { $massaction=''; }

$parameters=array();
$reshook=$hookmanager->executeHooks('doActions',$parameters);    // Note that $action and $object may have been modified by some hooks
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -119,9 +119,9 @@
 $search_employee=GETPOST('search_employee','alpha');
 $search_accountancy_code=GETPOST('search_accountancy_code','alpha');
 $search_email=GETPOST('search_email','alpha');
-$search_statut=GETPOST('search_statut','alpha');
+$search_statut=GETPOST('search_statut','intcomma');
 $search_thirdparty=GETPOST('search_thirdparty','alpha');
-$search_supervisor=GETPOST('search_supervisor','alpha');
+$search_supervisor=GETPOST('search_supervisor','intcomma');
 $search_previousconn=GETPOST('search_previousconn','alpha');
 $optioncss = GETPOST('optioncss','alpha');
 
@@ -148,7 +148,7 @@
     include DOL_DOCUMENT_ROOT.'/core/actions_changeselectedfields.inc.php';
 
     // Purge search criteria
-    if (GETPOST("button_removefilter_x") || GETPOST("button_removefilter.x") ||GETPOST("button_removefilter")) // All test are required to be compatible with all browsers
+    if (GETPOST("button_removefilter_x") || GETPOST("button_removefilter.x") ||GETPOST("button_removefilter")) // All tests are required to be compatible with all browsers
     {
     	$search_user="";
     	$search_login="";
@@ -203,8 +203,8 @@
 }
 if ($socid > 0) $sql.= " AND u.fk_soc = ".$socid;
 //if ($search_user != '')       $sql.=natural_search(array('u.login', 'u.lastname', 'u.firstname'), $search_user);
-if ($search_supervisor > 0)   $sql.= " AND u.fk_user = ".$search_supervisor;
-if ($search_thirdparty != '') $sql.=natural_search(array('s.nom'), $search_thirdparty);
+if ($search_supervisor > 0)   $sql.= " AND u.fk_user = ".$db->escape($search_supervisor);
+if ($search_thirdparty != '') $sql.= natural_search(array('s.nom'), $search_thirdparty);
 if ($search_login != '')      $sql.= natural_search("u.login", $search_login);
 if ($search_lastname != '')   $sql.= natural_search("u.lastname", $search_lastname);
 if ($search_firstname != '')  $sql.= natural_search("u.firstname", $search_firstname);
@@ -213,9 +213,9 @@
 	$sql .= ' AND u.employee = '.(int) $search_employee;
 }
 if ($search_accountancy_code != '')  $sql.= natural_search("u.accountancy_code", $search_accountancy_code);
-if ($search_email != '')  $sql.= natural_search("u.email", $search_email);
-if ($search_statut != '' && $search_statut >= 0) $sql.= " AND (u.statut=".$search_statut.")";
-if ($sall)                    $sql.= natural_search(array_keys($fieldstosearchall), $sall);
+if ($search_email != '')             $sql.= natural_search("u.email", $search_email);
+if ($search_statut != '' && $search_statut >= 0) $sql.= " AND u.statut IN (".$db->escape($search_statut).")";
+if ($sall)                           $sql.= natural_search(array_keys($fieldstosearchall), $sall);
 // Add where from extra fields
 foreach ($search_array_options as $key => $val)
 {
```
