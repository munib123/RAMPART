# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2979_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2979_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 50-91 of the vulnerable file.


$aColumns = trigger_change('user_list_columns', $aColumns);
	
/* Indexed column (used for fast and accurate table cardinality) */
$sIndexColumn = 'user_id';
	
/* DB table to use */
$sTable = USERS_TABLE.' INNER JOIN '.USER_INFOS_TABLE.' AS ui ON '.$conf['user_fields']['id'].' = ui.user_id';

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * If you just want to use the basic configuration for DataTables with PHP server-side, there is
 * no need to edit below this line
 */

/* 
 * Paging
 */
$sLimit = "";
if ( isset( $_REQUEST['iDisplayStart'] ) && $_REQUEST['iDisplayLength'] != '-1' )
{
  $sLimit = "LIMIT ".pwg_db_real_escape_string( $_REQUEST['iDisplayStart'] ).", ".
    pwg_db_real_escape_string( $_REQUEST['iDisplayLength'] );
}
	
	
/*
 * Ordering
 */
if ( isset( $_REQUEST['iSortCol_0'] ) )
{
  $sOrder = "ORDER BY  ";
  for ( $i=0 ; $i<intval( $_REQUEST['iSortingCols'] ) ; $i++ )
  {
    if ( $_REQUEST[ 'bSortable_'.intval($_REQUEST['iSortCol_'.$i]) ] == "true" )
    {
      $sOrder .= $aColumns[ intval( $_REQUEST['iSortCol_'.$i] ) ]."
				 	".pwg_db_real_escape_string( $_REQUEST['sSortDir_'.$i] ) .", ";
    }
  }
		
  $sOrder = substr_replace( $sOrder, "", -2 );
  if ( $sOrder == "ORDER BY" )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,8 +67,7 @@
 $sLimit = "";
 if ( isset( $_REQUEST['iDisplayStart'] ) && $_REQUEST['iDisplayLength'] != '-1' )
 {
-  $sLimit = "LIMIT ".pwg_db_real_escape_string( $_REQUEST['iDisplayStart'] ).", ".
-    pwg_db_real_escape_string( $_REQUEST['iDisplayLength'] );
+  $sLimit = "LIMIT ".$_REQUEST['iDisplayStart'].", ".$_REQUEST['iDisplayLength'];
 }
 	
 	
@@ -80,10 +79,13 @@
   $sOrder = "ORDER BY  ";
   for ( $i=0 ; $i<intval( $_REQUEST['iSortingCols'] ) ; $i++ )
   {
-    if ( $_REQUEST[ 'bSortable_'.intval($_REQUEST['iSortCol_'.$i]) ] == "true" )
-    {
-      $sOrder .= $aColumns[ intval( $_REQUEST['iSortCol_'.$i] ) ]."
-				 	".pwg_db_real_escape_string( $_REQUEST['sSortDir_'.$i] ) .", ";
+    check_input_parameter('iSortCol_'.$i, $_REQUEST, false, PATTERN_ID);
+
+    if ( $_REQUEST[ 'bSortable_'.$_REQUEST['iSortCol_'.$i] ] == "true" )
+    {
+      check_input_parameter('sSortDir_'.$i, $_REQUEST, false, '/^(asc|desc)$/');
+
+      $sOrder .= $aColumns[ $_REQUEST['iSortCol_'.$i] ].' '.$_REQUEST['sSortDir_'.$i].', ';
     }
   }
 		
```
