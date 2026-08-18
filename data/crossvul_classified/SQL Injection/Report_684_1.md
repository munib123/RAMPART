# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 684_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `684_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 71-111 of the vulnerable file.

}
if ($action == 'delete') {
	if ($cpt_id) {
		if ($accountingcategory->deleteCptCat($cpt_id)) {
			setEventMessages($langs->trans('CategoryDeleted'), null, 'mesgs');
		} else {
			setEventMessages($langs->trans('errors'), null, 'errors');
		}
	}
}


/*
 * View
 */
$form = new Form($db);
$formaccounting = new FormAccounting($db);

llxheader('', $langs->trans('AccountingCategory'));

$linkback = '<a href="'.DOL_URL_ROOT.'/accountancy/admin/categories_list.php?search_country_id='.$mysoc->country_id.'">'.$langs->trans("BackToList").'</a>';

print load_fiche_titre($langs->trans('AccountingCategory'), $linkback);

print '<form name="add" action="' . $_SERVER["PHP_SELF"] . '" method="POST">' . "\n";
print '<input type="hidden" name="token" value="' . $_SESSION['newtoken'] . '">';
print '<input type="hidden" name="action" value="display">';

dol_fiche_head();

print '<table class="border" width="100%">';
// Category
print '<tr><td class="titlefield">' . $langs->trans("AccountingCategory") . '</td>';
print '<td>';
$formaccounting->select_accounting_category($cat_id, 'account_category', 1, 0, 0, 1);
print '<input class="button" type="submit" value="' . $langs->trans("Select") . '">';
print '</td></tr>';

if (! empty($cat_id))
{
	$return = $accountingcategory->getAccountsWithNoCategory($cat_id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,7 +88,7 @@
 
 llxheader('', $langs->trans('AccountingCategory'));
 
-$linkback = '<a href="'.DOL_URL_ROOT.'/accountancy/admin/categories_list.php?search_country_id='.$mysoc->country_id.'">'.$langs->trans("BackToList").'</a>';
+$linkback = '<a href="'.DOL_URL_ROOT.'/accountancy/admin/categories_list.php?restore_lastsearch_values=1">'.$langs->trans("BackToList").'</a>';
 
 print load_fiche_titre($langs->trans('AccountingCategory'), $linkback);
 
```
