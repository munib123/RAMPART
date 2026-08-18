# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 471_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `471_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 934-974 of the vulnerable file.

		print '<tr><td id="tdcompany">'.$langs->trans("Company").'</td><td><input type="text" name="societe" class="minwidth300" maxlength="128" value="'.(GETPOST('societe','alpha')?GETPOST('societe','alpha'):$object->societe).'"></td></tr>';

		// Civility
		print '<tr><td>'.$langs->trans("UserTitle").'</td><td>';
		print $formcompany->select_civility(GETPOST('civility_id','int')?GETPOST('civility_id','int'):$object->civility_id,'civility_id').'</td>';
		print '</tr>';

		// Lastname
		print '<tr><td id="tdlastname">'.$langs->trans("Lastname").'</td><td><input type="text" name="lastname" class="minwidth300" maxlength="50" value="'.(GETPOST('lastname','alpha')?GETPOST('lastname','alpha'):$object->lastname).'"></td>';
		print '</tr>';

		// Firstname
		print '<tr><td id="tdfirstname">'.$langs->trans("Firstname").'</td><td><input type="text" name="firstname" class="minwidth300" maxlength="50" value="'.(GETPOST('firstname','alpha')?GETPOST('firstname','alpha'):$object->firstname).'"></td>';
		print '</tr>';

		// EMail
		print '<tr><td>'.($conf->global->ADHERENT_MAIL_REQUIRED?'<span class="fieldrequired">':'').$langs->trans("EMail").($conf->global->ADHERENT_MAIL_REQUIRED?'</span>':'').'</td><td><input type="text" name="member_email" class="minwidth300" maxlength="255" value="'.(GETPOST('member_email','alpha')?GETPOST('member_email','alpha'):$object->email).'"></td></tr>';

		// Address
		print '<tr><td class="tdtop">'.$langs->trans("Address").'</td><td>';
		print '<textarea name="address" wrap="soft" class="quatrevingtpercent" rows="2">'.(GETPOST('address','alpha')?GETPOST('address','alpha'):$object->address).'</textarea>';
		print '</td></tr>';

		// Zip / Town
		print '<tr><td>'.$langs->trans("Zip").' / '.$langs->trans("Town").'</td><td>';
		print $formcompany->select_ziptown((GETPOST('zipcode','alpha')?GETPOST('zipcode','alpha'):$object->zip),'zipcode',array('town','selectcountry_id','state_id'),6);
		print ' ';
		print $formcompany->select_ziptown((GETPOST('town','alpha')?GETPOST('town','alpha'):$object->town),'town',array('zipcode','selectcountry_id','state_id'));
		print '</td></tr>';

		// Country
		$object->country_id=$object->country_id?$object->country_id:$mysoc->country_id;
		print '<tr><td width="25%">'.$langs->trans('Country').'</td><td>';
		print $form->select_country(GETPOST('country_id','alpha')?GETPOST('country_id','alpha'):$object->country_id,'country_id');
		if ($user->admin) print info_admin($langs->trans("YouCanChangeValuesForThisListFromDictionarySetup"),1);
		print '</td></tr>';

		// State
		if (empty($conf->global->MEMBER_DISABLE_STATE))
		{
			print '<tr><td>'.$langs->trans('State').'</td><td>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -951,14 +951,14 @@
 
 		// Address
 		print '<tr><td class="tdtop">'.$langs->trans("Address").'</td><td>';
-		print '<textarea name="address" wrap="soft" class="quatrevingtpercent" rows="2">'.(GETPOST('address','alpha')?GETPOST('address','alpha'):$object->address).'</textarea>';
+		print '<textarea name="address" wrap="soft" class="quatrevingtpercent" rows="2">'.(GETPOST('address','alphanohtml')?GETPOST('address','alphanohtml'):$object->address).'</textarea>';
 		print '</td></tr>';
 
 		// Zip / Town
 		print '<tr><td>'.$langs->trans("Zip").' / '.$langs->trans("Town").'</td><td>';
-		print $formcompany->select_ziptown((GETPOST('zipcode','alpha')?GETPOST('zipcode','alpha'):$object->zip),'zipcode',array('town','selectcountry_id','state_id'),6);
+		print $formcompany->select_ziptown((GETPOST('zipcode','alphanohtml')?GETPOST('zipcode','alphanohtml'):$object->zip),'zipcode',array('town','selectcountry_id','state_id'),6);
 		print ' ';
-		print $formcompany->select_ziptown((GETPOST('town','alpha')?GETPOST('town','alpha'):$object->town),'town',array('zipcode','selectcountry_id','state_id'));
+		print $formcompany->select_ziptown((GETPOST('town','alphanohtml')?GETPOST('town','alphanohtml'):$object->town),'town',array('zipcode','selectcountry_id','state_id'));
 		print '</td></tr>';
 
 		// Country
```
