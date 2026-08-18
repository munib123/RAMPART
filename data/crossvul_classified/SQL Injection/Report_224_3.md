# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 224_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `224_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 70-97 of the vulnerable file.

}
else
{
	require_once DOL_DOCUMENT_ROOT.'/core/class/html.form.class.php';

	$langs->load("companies");

	top_httphead();

	if (empty($htmlname)) return;

	$match = preg_grep('/('.$htmlname.'[0-9]+)/',array_keys($_GET));
	sort($match);
	$id = (! empty($match[0]) ? $match[0] : '');

	// When used from jQuery, the search term is added as GET param "term".
	$searchkey=(($id && GETPOST($id, 'alpha'))?GETPOST($id, 'alpha'):(($htmlname && GETPOST($htmlname, 'alpha'))?GETPOST($htmlname, 'alpha'):''));

	if (! $searchkey) return;

	$form = new Form($db);
	$arrayresult=$form->select_thirdparty_list(0, $htmlname, $filter, 1, $showtype, 0, null, $searchkey, $outjson);

	$db->close();

	if ($outjson) print json_encode($arrayresult);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,7 +87,7 @@
 
 	if (! $searchkey) return;
 
-	$form = new Form($db);
+	if (! is_object($form)) $form = new Form($db);
 	$arrayresult=$form->select_thirdparty_list(0, $htmlname, $filter, 1, $showtype, 0, null, $searchkey, $outjson);
 
 	$db->close();
```
