# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 684_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `684_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 37-78 of the vulnerable file.

$confirm=GETPOST('confirm','alpha');
$id=32;
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
$page = GETPOST("page",'int');
if (empty($page) || $page == -1) { $page = 0; }     // If $page is not defined, or '' or -1
$offset = $listlimit * $page ;
$pageprev = $page - 1;
$pagenext = $page + 1;

$search_country_id = GETPOST('search_country_id','int');

// Initialize technical object to manage hooks of page. Note that conf->hooks_modules contains array of hook context
$hookmanager->initHooks(array('admin'));

// This page is a generic page to edit dictionaries
// Put here declaration of dictionaries properties

// Sort order to show dictionary (0 is space). All other dictionaries (added by modules) will be at end of this.
$taborder=array(32);

// Name of SQL tables of dictionaries
$tabname=array();
$tabname[32]= MAIN_DB_PREFIX."c_accounting_category";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,8 +54,8 @@
 $listlimit=GETPOST('listlimit')>0?GETPOST('listlimit'):1000;
 $active = 1;
 
-$sortfield = GETPOST("sortfield",'alpha');
-$sortorder = GETPOST("sortorder",'alpha');
+$sortfield = GETPOST("sortfield",'aZ09comma');
+$sortorder = GETPOST("sortorder",'aZ09comma');
 $page = GETPOST("page",'int');
 if (empty($page) || $page == -1) { $page = 0; }     // If $page is not defined, or '' or -1
 $offset = $listlimit * $page ;
@@ -300,7 +300,7 @@
     if ($tabrowid[$id]) { $rowidcol=$tabrowid[$id]; }
     else { $rowidcol="rowid"; }
 
-    $sql = "DELETE from ".$tabname[$id]." WHERE ".$rowidcol." = '".$this->db->escape($rowid)."'";
+    $sql = "DELETE from ".$tabname[$id]." WHERE ".$rowidcol." = '".$db->escape($rowid)."'";
 
     dol_syslog("delete", LOG_DEBUG);
     $result = $db->query($sql);
@@ -324,10 +324,10 @@
     else { $rowidcol="rowid"; }
 
     if ($rowid) {
-        $sql = "UPDATE ".$tabname[$id]." SET active = 1 WHERE ".$rowidcol." = '".$this->db->escape($rowid)."'";
+        $sql = "UPDATE ".$tabname[$id]." SET active = 1 WHERE ".$rowidcol." = '".$db->escape($rowid)."'";
     }
     elseif ($code) {
-    	$sql = "UPDATE ".$tabname[$id]." SET active = 1 WHERE code = '".$this->db->escape($code)."'";
+    	$sql = "UPDATE ".$tabname[$id]." SET active = 1 WHERE code = '".$db->escape($code)."'";
     }
 
     $result = $db->query($sql);
@@ -344,10 +344,10 @@
     else { $rowidcol="rowid"; }
 
     if ($rowid) {
-    	$sql = "UPDATE ".$tabname[$id]." SET active = 0 WHERE ".$rowidcol." = '".$this->db->escape($rowid)."'";
+    	$sql = "UPDATE ".$tabname[$id]." SET active = 0 WHERE ".$rowidcol." = '".$db->escape($rowid)."'";
     }
     elseif ($code) {
-    	$sql = "UPDATE ".$tabname[$id]." SET active = 0 WHERE code = '".$this->db->escape($code)."'";
+    	$sql = "UPDATE ".$tabname[$id]." SET active = 0 WHERE code = '".$db->escape($code)."'";
     }
 
     $result = $db->query($sql);
@@ -364,10 +364,10 @@
     else { $rowidcol="rowid"; }
 
     if ($rowid) {
-    	$sql = "UPDATE ".$tabname[$id]." SET favorite = 1 WHERE ".$rowidcol." = '".$this->db->escape($rowid)."'";
+    	$sql = "UPDATE ".$tabname[$id]." SET favorite = 1 WHERE ".$rowidcol." = '".$db->escape($rowid)."'";
     }
     elseif ($code) {
-    	$sql = "UPDATE ".$tabname[$id]." SET favorite = 1 WHERE code = '".$this->db->escape($code)."'";
+    	$sql = "UPDATE ".$tabname[$id]." SET favorite = 1 WHERE code = '".$db->escape($code)."'";
     }
 
     $result = $db->query($sql);
@@ -384,10 +384,10 @@
     else { $rowidcol="rowid"; }
 
     if ($rowid) {
-    	$sql = "UPDATE ".$tabname[$id]." SET favorite = 0 WHERE ".$rowidcol." = '".$this->db->escape($rowid)."'";
+    	$sql = "UPDATE ".$tabname[$id]." SET favorite = 0 WHERE ".$rowidcol." = '".$db->escape($rowid)."'";
     }
     elseif ($code) {
-    	$sql = "UPDATE ".$tabname[$id]." SET favorite = 0 WHERE code = '".$this->db->escape($code)."'";
+    	$sql = "UPDATE ".$tabname[$id]." SET favorite = 0 WHERE code = '".$db->escape($code)."'";
     }
 
     $result = $db->query($sql);
@@ -437,24 +437,9 @@
         $sql.= " (a.fk_country = ".$search_country_id." OR a.fk_country = 0)";
     }
 
-    if ($sortfield)
-    {
-        // If sort order is "country", we use country_code instead
-    	if ($sortfield == 'country') $sortfield='country_code';
-        $sql.= " ORDER BY ".$sortfield;
-        if ($sortorder)
-        {
-            $sql.=" ".strtoupper($sortorder);
-        }
-        $sql.=", ";
-        // Clear the required sort criteria for the tabsqlsort to be able to force it with selected value
-        $tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.' '.$sortorder.',/i','',$tabsqlsort[$id]);
-        $tabsqlsort[$id]=preg_replace('/([a-z]+\.)?'.$sortfield.',/i','',$tabsqlsort[$id]);
-    }
-    else {
-        $sql.=" ORDER BY ";
-    }
-    $sql.=$tabsqlsort[$id];
+    // If sort order is "country", we use country_code instead
+    if ($sortfield == 'country') $sortfield='country_code';
+    $sql.=$db->order($sortfield,$sortorder);
     $sql.=$db->plimit($listlimit+1,$offset);
     //print $sql;
 
@@ -793,7 +778,7 @@
                     print '<td class="center">';
                     if (empty($obj->formula))
                     {
-                        print '<a href="'.DOL_URL_ROOT.'/accountancy/admin/categories.php?action=display&account_category='.$obj->rowid.'">';
+                        print '<a href="'.DOL_URL_ROOT.'/accountancy/admin/categories.php?action=display&save_lastsearch_values=1&account_category='.$obj->rowid.'">';
                         print $langs->trans("ListOfAccounts");
                         print '</a>';
                     }
```
