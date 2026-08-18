# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2791_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2791_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 328-368 of the vulnerable file.

	print "<tr>".'<td>'.$langs->trans("Address").'</td><td>';
	print '<textarea name="address" wrap="soft" class="quatrevingtpercent" rows="3">'.dol_escape_htmltag(GETPOST("address")).'</textarea></td></tr>';

    // Zip / Town
    print '<tr><td>'.$langs->trans("Zip").' / '.$langs->trans("Town").'</td><td>';
	print $formcompany->select_ziptown((isset($_POST["zipcode"])?$_POST["zipcode"]:$object->zip),'zipcode',array('town','selectcountry_id','state_id'),6);
    print ' ';
    print $formcompany->select_ziptown((isset($_POST["town"])?$_POST["town"]:$object->town),'town',array('zipcode','selectcountry_id','state_id'));
    print '</tr>';

	// Country
    print '<tr><td><label for="selectcountry_id">'.$langs->trans('Country').'</label></td><td class="maxwidthonsmartphone">';
    print $form->select_country(GETPOST('country_id')!=''?GETPOST('country_id'):$object->country_id);
    if ($user->admin) print info_admin($langs->trans("YouCanChangeValuesForThisListFromDictionarySetup"),1);
    print '</td></tr>';

	print "<tr>".'<td>'.$langs->trans("EMail").'</td><td><input type="text" name="email" value="'.dol_escape_htmltag(GETPOST("email")).'" class="maxwidth200"></td></tr>';

	// Public note
	print '<tr>';
	print '<td class="border" valign="top">' . $langs->trans('NotePublic') . '</td>';
	print '<td>';

    $doleditor = new DolEditor('note_public', $note_public, '', 80, 'dolibarr_notes', 'In', 0, false, true, ROWS_3, '90%');
	print $doleditor->Create(1);
	print '</td></tr>';

	// Private note
	if (empty($user->societe_id)) {
		print '<tr>';
		print '<td class="border" valign="top">' . $langs->trans('NotePrivate') . '</td>';
		print '<td>';

		$doleditor = new DolEditor('note_private', $note_private, '', 80, 'dolibarr_notes', 'In', 0, false, true, ROWS_3, '90%');
		print $doleditor->Create(1);
		print '</td></tr>';
	}

	if (! empty($conf->projet->enabled))
    {
        print "<tr><td>".$langs->trans("Project")."</td><td>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -345,7 +345,7 @@
 
 	// Public note
 	print '<tr>';
-	print '<td class="border" valign="top">' . $langs->trans('NotePublic') . '</td>';
+	print '<td class="tdtop">' . $langs->trans('NotePublic') . '</td>';
 	print '<td>';
 
     $doleditor = new DolEditor('note_public', $note_public, '', 80, 'dolibarr_notes', 'In', 0, false, true, ROWS_3, '90%');
@@ -355,7 +355,7 @@
 	// Private note
 	if (empty($user->societe_id)) {
 		print '<tr>';
-		print '<td class="border" valign="top">' . $langs->trans('NotePrivate') . '</td>';
+		print '<td class="tdtop">' . $langs->trans('NotePrivate') . '</td>';
 		print '<td>';
 
 		$doleditor = new DolEditor('note_private', $note_private, '', 80, 'dolibarr_notes', 'In', 0, false, true, ROWS_3, '90%');
@@ -542,7 +542,7 @@
 	$hselected='card';
 
 	$head = donation_prepare_head($object);
-	dol_fiche_head($head, $hselected, $langs->trans("Donation"), 0, 'generic');
+	dol_fiche_head($head, $hselected, $langs->trans("Donation"), -1, 'generic');
 
 	// Print form confirm
 	print $formconfirm;
```
