# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 169-209 of the vulnerable file.


/*
 * 	Database retrieve information for differents elements list we need on the page
 */

/*
 * Host Templates comes from DB -> Store in $hosts Array
 */
$hosts = array();
$DBRESULT = $pearDB->query("SELECT host_id, host_name FROM host WHERE host_register = '0' ORDER BY host_name");
while ($host = $DBRESULT->fetchRow()) {
    $hosts[$host["host_id"]] = $host["host_name"];
 }
$DBRESULT->free();

/*
 * Get all Templates who use himself
 */
$svc_tmplt_who_use_me = array();
if (isset($_GET["service_id"]) && $_GET["service_id"]) {
    $DBRESULT = $pearDB->query("SELECT service_description, service_id FROM service WHERE service_template_model_stm_id = '".$_GET["service_id"]."'");
    while ($service_tmpl_father = $DBRESULT->fetchRow()) {
        $svc_tmplt_who_use_me[$service_tmpl_father["service_id"]] = $service_tmpl_father["service_description"];
    }
    $DBRESULT->free();
 }

/*
 * Service Templates comes from DB -> Store in $svTpls Array
 */
$svTpls = array(NULL=>NULL);
$DBRESULT = $pearDB->query("SELECT service_id, service_description, service_template_model_stm_id FROM service WHERE service_register = '0' AND service_id != '".$service_id."' ORDER BY service_description");
while ($svTpl = $DBRESULT->fetchRow())	{
    if (!$svTpl["service_description"]) {
        $svTpl["service_description"] = getMyServiceName($svTpl["service_template_model_stm_id"])."'";
    } else {
        $svTpl["service_description"] = str_replace('#S#', "/", $svTpl["service_description"]);
        $svTpl["service_description"] = str_replace('#BS#', "\\", $svTpl["service_description"]);
    }
    if (!isset($svc_tmplt_who_use_me[$svTpl["service_id"]]) || !$svc_tmplt_who_use_me[$svTpl["service_id"]]) {
        $svTpls[$svTpl["service_id"]] = $svTpl["service_description"];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -186,7 +186,7 @@
  */
 $svc_tmplt_who_use_me = array();
 if (isset($_GET["service_id"]) && $_GET["service_id"]) {
-    $DBRESULT = $pearDB->query("SELECT service_description, service_id FROM service WHERE service_template_model_stm_id = '".$_GET["service_id"]."'");
+    $DBRESULT = $pearDB->query("SELECT service_description, service_id FROM service WHERE service_template_model_stm_id = '".$pearDB->escape($_GET["service_id"])."'");
     while ($service_tmpl_father = $DBRESULT->fetchRow()) {
         $svc_tmplt_who_use_me[$service_tmpl_father["service_id"]] = $service_tmpl_father["service_description"];
     }
@@ -196,7 +196,7 @@
 /*
  * Service Templates comes from DB -> Store in $svTpls Array
  */
-$svTpls = array(NULL=>NULL);
+$svTpls = array(NULL => NULL);
 $DBRESULT = $pearDB->query("SELECT service_id, service_description, service_template_model_stm_id FROM service WHERE service_register = '0' AND service_id != '".$service_id."' ORDER BY service_description");
 while ($svTpl = $DBRESULT->fetchRow())	{
     if (!$svTpl["service_description"]) {
```
