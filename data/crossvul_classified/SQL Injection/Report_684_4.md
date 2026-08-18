# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 684_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `684_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 948-989 of the vulnerable file.

{
    $titre=$langs->trans("MenuVatAccounts");
    $titlepicto='title_accountancy';
}
if ($id == 7 && GETPOST('from') == 'accountancy')
{
    $titre=$langs->trans("MenuTaxAccounts");
    $titlepicto='title_accountancy';
}

print load_fiche_titre($titre,$linkback,$titlepicto);

if (empty($id))
{
    print $langs->trans("DictionaryDesc");
    print " ".$langs->trans("OnlyActiveElementsAreShown")."<br>\n";
}
print "<br>\n";


$param = '&id='.$id;
if ($search_country_id > 0) $param.= '&search_country_id='.$search_country_id;
if ($search_code != '')     $param.= '&search_code='.urlencode($search_country_id);
if ($entity != '') $param.= '&entity=' . (int) $entity;
$paramwithsearch = $param;
if ($sortorder) $paramwithsearch.= '&sortorder='.$sortorder;
if ($sortfield) $paramwithsearch.= '&sortfield='.$sortfield;
if (GETPOST('from')) $paramwithsearch.= '&from='.GETPOST('from','alpha');


// Confirmation de la suppression de la ligne
if ($action == 'delete')
{
    print $form->formconfirm($_SERVER["PHP_SELF"].'?'.($page?'page='.$page.'&':'').'rowid='.$rowid.'&code='.urlencode($code).$paramwithsearch, $langs->trans('DeleteLine'), $langs->trans('ConfirmDeleteLine'), 'confirm_delete','',0,1);
}
//var_dump($elementList);

/*
 * Show a dictionary
 */
if ($id)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -965,14 +965,14 @@
 print "<br>\n";
 
 
-$param = '&id='.$id;
-if ($search_country_id > 0) $param.= '&search_country_id='.$search_country_id;
+$param = '&id='.urlencode($id);
+if ($search_country_id > 0) $param.= '&search_country_id='.urlencode($search_country_id);
 if ($search_code != '')     $param.= '&search_code='.urlencode($search_country_id);
 if ($entity != '') $param.= '&entity=' . (int) $entity;
 $paramwithsearch = $param;
-if ($sortorder) $paramwithsearch.= '&sortorder='.$sortorder;
-if ($sortfield) $paramwithsearch.= '&sortfield='.$sortfield;
-if (GETPOST('from')) $paramwithsearch.= '&from='.GETPOST('from','alpha');
+if ($sortorder) $paramwithsearch.= '&sortorder='.urlencode($sortorder);
+if ($sortfield) $paramwithsearch.= '&sortfield='.urlencode($sortfield);
+if (GETPOST('from')) $paramwithsearch.= '&from='.urlencode(GETPOST('from','alpha'));
 
 
 // Confirmation de la suppression de la ligne
@@ -999,10 +999,10 @@
     {
         // If sort order is "country", we use country_code instead
     	if ($sortfield == 'country') $sortfield='country_code';
-        $sql.= " ORDER BY ".$sortfield;
+        $sql.= " ORDER BY ".$db->escape($sortfield);
         if ($sortorder)
         {
-            $sql.=" ".strtoupper($sortorder);
+        	$sql.=" ".strtoupper($db->escape($sortorder));
         }
         $sql.=", ";
         // Clear the required sort criteria for the tabsqlsort to be able to force it with selected value
```
