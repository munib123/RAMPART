# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 135-175 of the vulnerable file.

        /*
         * Preset values of host templates
         */
        $tplArray = $hostObj->getTemplates(isset($host_id) ? $host_id : null);
        $cdata->addJsData('clone-values-template', htmlspecialchars(
                                    json_encode($tplArray), 
                                    ENT_QUOTES
                                )
        );
        $cdata->addJsData('clone-count-template', count($tplArray));
        
	#
	## Database retrieve information for differents elements list we need on the page
	#

	/*
	 * Get all Templates who use himself
	 */
	$host_tmplt_who_use_me = array();
	if (isset($_GET["host_id"]) && $_GET["host_id"]){
		$DBRESULT = $pearDB->query("SELECT host_id, host_name FROM host WHERE host_template_model_htm_id = '".$_GET["host_id"]."'");
		while($host_tmpl_father = $DBRESULT->fetchRow())
			$host_tmplt_who_use_me[$host_tmpl_father["host_id"]] = $host_tmpl_father["host_name"];
		$DBRESULT->free();
	}

	/*
	 * Host Templates comes from DB -> Store in $hTpls Array
	 */
	$hTpls = array(NULL=>NULL);
	$DBRESULT = $pearDB->query("SELECT host_id, host_name, host_template_model_htm_id FROM host WHERE host_register = '0' AND host_id != '".$host_id."' ORDER BY host_name");
	while($hTpl = $DBRESULT->fetchRow())	{
		if (!$hTpl["host_name"])
			$hTpl["host_name"] = getMyHostName($hTpl["host_template_model_htm_id"])."'";
		if (!isset($host_tmplt_who_use_me[$hTpl["host_id"]]))
			$hTpls[$hTpl["host_id"]] = $hTpl["host_name"];
	}
	$DBRESULT->free();
	# Service Templates comes from DB -> Store in $svTpls Array
	$svTpls = array();
	$DBRESULT = $pearDB->query("SELECT service_id, service_description, service_template_model_stm_id FROM service WHERE service_register = '0' ORDER BY service_description");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,7 +152,7 @@
 	 */
 	$host_tmplt_who_use_me = array();
 	if (isset($_GET["host_id"]) && $_GET["host_id"]){
-		$DBRESULT = $pearDB->query("SELECT host_id, host_name FROM host WHERE host_template_model_htm_id = '".$_GET["host_id"]."'");
+		$DBRESULT = $pearDB->query("SELECT host_id, host_name FROM host WHERE host_template_model_htm_id = '".$pearDB->escape($_GET["host_id"])."'");
 		while($host_tmpl_father = $DBRESULT->fetchRow())
 			$host_tmplt_who_use_me[$host_tmpl_father["host_id"]] = $host_tmpl_father["host_name"];
 		$DBRESULT->free();
```
