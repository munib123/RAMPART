# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 474_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `474_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 174-216 of the vulnerable file.

		}

		if (!empty($conf->file->main_limit_users)) { // If option to limit users is set
			$nb = $object->getNbOfUsers("active");
			if ($nb >= $conf->file->main_limit_users) {
				$error ++;
				setEventMessages($langs->trans("YourQuotaOfUsersIsReached"), null, 'errors');
				$action = "create";       // Go back to create page
			}
		}

		if (!$error) {
			$object->lastname = GETPOST("lastname", 'alpha');
			$object->firstname = GETPOST("firstname", 'alpha');
			$object->login = GETPOST("login", 'alpha');
			$object->api_key = GETPOST("api_key", 'alpha');
			$object->gender = GETPOST("gender", 'alpha');
			$birth = dol_mktime(0, 0, 0, GETPOST('birthmonth'), GETPOST('birthday'), GETPOST('birthyear'));
			$object->birth = $birth;
			$object->admin = GETPOST("admin", 'alpha');
			$object->address = GETPOST('address', 'alpha');
			$object->zip = GETPOST('zipcode', 'alpha');
			$object->town = GETPOST('town', 'alpha');
			$object->country_id = GETPOST('country_id', 'int');
			$object->state_id = GETPOST('state_id', 'int');
			$object->office_phone = GETPOST("office_phone", 'alpha');
			$object->office_fax = GETPOST("office_fax", 'alpha');
			$object->user_mobile = GETPOST("user_mobile");
			$object->skype = GETPOST("skype", 'alpha');
			$object->email = preg_replace('/\s+/', '', GETPOST("email", 'alpha'));
			$object->job = GETPOST("job", 'alpha');
			$object->signature = GETPOST("signature");
			$object->accountancy_code = GETPOST("accountancy_code");
			$object->note = GETPOST("note");
			$object->ldap_sid = GETPOST("ldap_sid");
			$object->fk_user = GETPOST("fk_user") > 0 ? GETPOST("fk_user") : 0;
			$object->employee = GETPOST('employee');

			$object->thm = GETPOST("thm") != '' ? GETPOST("thm") : '';
			$object->tjm = GETPOST("tjm") != '' ? GETPOST("tjm") : '';
			$object->salary = GETPOST("salary") != '' ? GETPOST("salary") : '';
			$object->salaryextra = GETPOST("salaryextra") != '' ? GETPOST("salaryextra") : '';
			$object->weeklyhours = GETPOST("weeklyhours") != '' ? GETPOST("weeklyhours") : '';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -191,31 +191,31 @@
 			$birth = dol_mktime(0, 0, 0, GETPOST('birthmonth'), GETPOST('birthday'), GETPOST('birthyear'));
 			$object->birth = $birth;
 			$object->admin = GETPOST("admin", 'alpha');
-			$object->address = GETPOST('address', 'alpha');
-			$object->zip = GETPOST('zipcode', 'alpha');
-			$object->town = GETPOST('town', 'alpha');
+			$object->address = GETPOST('address', 'alphanohtml');
+			$object->zip = GETPOST('zipcode', 'alphanohtml');
+			$object->town = GETPOST('town', 'alphanohtml');
 			$object->country_id = GETPOST('country_id', 'int');
 			$object->state_id = GETPOST('state_id', 'int');
-			$object->office_phone = GETPOST("office_phone", 'alpha');
-			$object->office_fax = GETPOST("office_fax", 'alpha');
-			$object->user_mobile = GETPOST("user_mobile");
-			$object->skype = GETPOST("skype", 'alpha');
+			$object->office_phone = GETPOST("office_phone", 'alphanohtml');
+			$object->office_fax = GETPOST("office_fax", 'alphanohtml');
+			$object->user_mobile = GETPOST("user_mobile", 'alphanohtml');
+			$object->skype = GETPOST("skype", 'alphanohtml');
 			$object->email = preg_replace('/\s+/', '', GETPOST("email", 'alpha'));
 			$object->job = GETPOST("job", 'alpha');
-			$object->signature = GETPOST("signature");
-			$object->accountancy_code = GETPOST("accountancy_code");
-			$object->note = GETPOST("note");
-			$object->ldap_sid = GETPOST("ldap_sid");
-			$object->fk_user = GETPOST("fk_user") > 0 ? GETPOST("fk_user") : 0;
-			$object->employee = GETPOST('employee');
-
-			$object->thm = GETPOST("thm") != '' ? GETPOST("thm") : '';
-			$object->tjm = GETPOST("tjm") != '' ? GETPOST("tjm") : '';
-			$object->salary = GETPOST("salary") != '' ? GETPOST("salary") : '';
-			$object->salaryextra = GETPOST("salaryextra") != '' ? GETPOST("salaryextra") : '';
-			$object->weeklyhours = GETPOST("weeklyhours") != '' ? GETPOST("weeklyhours") : '';
-
-			$object->color = GETPOST("color") != '' ? GETPOST("color") : '';
+			$object->signature = GETPOST("signature", 'none');
+			$object->accountancy_code = GETPOST("accountancy_code", 'alphanohtml');
+			$object->note = GETPOST("note", 'none');
+			$object->ldap_sid = GETPOST("ldap_sid", 'alphanohtml');
+			$object->fk_user = GETPOST("fk_user", 'int') > 0 ? GETPOST("fk_user", 'int') : 0;
+			$object->employee = GETPOST('employee', 'alphanohtml');
+
+			$object->thm = GETPOST("thm", 'alphanohtml') != '' ? GETPOST("thm", 'alphanohtml') : '';
+			$object->tjm = GETPOST("tjm", 'alphanohtml') != '' ? GETPOST("tjm", 'alphanohtml') : '';
+			$object->salary = GETPOST("salary", 'alphanohtml') != '' ? GETPOST("salary", 'alphanohtml') : '';
+			$object->salaryextra = GETPOST("salaryextra", 'alphanohtml') != '' ? GETPOST("salaryextra", 'alphanohtml') : '';
+			$object->weeklyhours = GETPOST("weeklyhours", 'alphanohtml') != '' ? GETPOST("weeklyhours", 'alphanohtml') : '';
+
+			$object->color = GETPOST("color", 'alphanohtml') != '' ? GETPOST("color", 'alphanohtml') : '';
 			$dateemployment = dol_mktime(0, 0, 0, GETPOST('dateemploymentmonth'), GETPOST('dateemploymentday'), GETPOST('dateemploymentyear'));
 			$object->dateemployment = $dateemployment;
 
@@ -335,14 +335,14 @@
 				$object->pass = GETPOST("password",'none');
 				$object->api_key = (GETPOST("api_key", 'alpha')) ? GETPOST("api_key", 'alpha') : $object->api_key;
 				if (! empty($user->admin)) $object->admin = GETPOST("admin"); 	// admin flag can only be set/unset by an admin user. A test is also done later when forging sql request
-				$object->address = GETPOST('address', 'alpha');
-				$object->zip = GETPOST('zipcode', 'alpha');
-				$object->town = GETPOST('town', 'alpha');
+				$object->address = GETPOST('address', 'alphanohtml');
+				$object->zip = GETPOST('zipcode', 'alphanohtml');
+				$object->town = GETPOST('town', 'alphanohtml');
 				$object->country_id = GETPOST('country_id', 'int');
 				$object->state_id = GETPOST('state_id', 'int');
-				$object->office_phone = GETPOST("office_phone", 'alpha');
-				$object->office_fax = GETPOST("office_fax", 'alpha');
-				$object->user_mobile = GETPOST("user_mobile");
+				$object->office_phone = GETPOST("office_phone", 'alphanohtml');
+				$object->office_fax = GETPOST("office_fax", 'alphanohtml');
+				$object->user_mobile = GETPOST("user_mobile", 'alphanohtml');
 				$object->skype = GETPOST("skype", 'alpha');
 				$object->email = preg_replace('/\s+/', '', GETPOST("email", 'alpha'));
 				$object->job = GETPOST("job", 'alpha');
@@ -350,7 +350,7 @@
 				$object->accountancy_code = GETPOST("accountancy_code",'alpha');
 				$object->openid = GETPOST("openid",'alpha');
 				$object->fk_user = GETPOST("fk_user",'int') > 0 ? GETPOST("fk_user",'int') : 0;
-				$object->employee = GETPOST('employee');
+				$object->employee = GETPOST('employee','alphanothtml');
 
 				$object->thm = GETPOST("thm",'alphanohtml') != '' ? GETPOST("thm",'alphanohtml') : '';
 				$object->tjm = GETPOST("tjm",'alphanohtml') != '' ? GETPOST("tjm",'alphanohtml') : '';
```
