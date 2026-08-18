# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5637_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5637_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 941-981 of the vulnerable file.

	if ($action == 'edit')
	{
		/********************************************
		 *
		* Fiche en mode edition
		*
		********************************************/

		$res=$object->fetch($rowid);
		if ($res < 0) {
			dol_print_error($db,$object->error); exit;
		}
		$res=$object->fetch_optionals($object->id,$extralabels);
		if ($res < 0) {
			dol_print_error($db); exit;
		}

		$adht = new AdherentType($db);
		$adht->fetch($object->typeid);

		// We set country_id, and country_code, country of the chosen country
		if (isset($_POST["pays"]) || $object->country_id)
		{
			$sql = "SELECT rowid, code, libelle as label from ".MAIN_DB_PREFIX."c_pays where rowid = ".(isset($_POST["pays"])?$_POST["pays"]:$object->country_id);
			$resql=$db->query($sql);
			if ($resql)
			{
				$obj = $db->fetch_object($resql);
			}
			else
			{
				dol_print_error($db);
			}
			$object->pays_id=$obj->rowid;
			$object->pays_code=$obj->code;
			$object->pays=$langs->trans("Country".$obj->code)?$langs->trans("Country".$obj->code):$obj->label;
			$object->country_id=$obj->rowid;
			$object->country_code=$obj->code;
			$object->country=$langs->trans("Country".$obj->code)?$langs->trans("Country".$obj->code):$obj->label;
		}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -958,10 +958,11 @@
 		$adht = new AdherentType($db);
 		$adht->fetch($object->typeid);
 
+		$country=GETPOST('pays','int');
 		// We set country_id, and country_code, country of the chosen country
-		if (isset($_POST["pays"]) || $object->country_id)
-		{
-			$sql = "SELECT rowid, code, libelle as label from ".MAIN_DB_PREFIX."c_pays where rowid = ".(isset($_POST["pays"])?$_POST["pays"]:$object->country_id);
+		if (!empty($country) || $object->country_id)
+		{
+			$sql = "SELECT rowid, code, libelle as label from ".MAIN_DB_PREFIX."c_pays where rowid = ".(!empty($country)?$country:$object->country_id);
 			$resql=$db->query($sql);
 			if ($resql)
 			{
```
