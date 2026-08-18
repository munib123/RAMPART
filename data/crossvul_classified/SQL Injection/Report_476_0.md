# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 476_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `476_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 333-373 of the vulnerable file.

				$birth = dol_mktime(0, 0, 0, GETPOST('birthmonth'), GETPOST('birthday'), GETPOST('birthyear'));
				$object->birth = $birth;
				$object->pass = GETPOST("password",'none');
				$object->api_key = (GETPOST("api_key", 'alpha')) ? GETPOST("api_key", 'alpha') : $object->api_key;
				if (! empty($user->admin)) $object->admin = GETPOST("admin"); 	// admin flag can only be set/unset by an admin user. A test is also done later when forging sql request
				$object->address = GETPOST('address', 'alphanohtml');
				$object->zip = GETPOST('zipcode', 'alphanohtml');
				$object->town = GETPOST('town', 'alphanohtml');
				$object->country_id = GETPOST('country_id', 'int');
				$object->state_id = GETPOST('state_id', 'int');
				$object->office_phone = GETPOST("office_phone", 'alphanohtml');
				$object->office_fax = GETPOST("office_fax", 'alphanohtml');
				$object->user_mobile = GETPOST("user_mobile", 'alphanohtml');
				$object->skype = GETPOST("skype", 'alpha');
				$object->email = preg_replace('/\s+/', '', GETPOST("email", 'alpha'));
				$object->job = GETPOST("job", 'alpha');
				$object->signature = GETPOST("signature",'none');
				$object->accountancy_code = GETPOST("accountancy_code",'alpha');
				$object->openid = GETPOST("openid",'alpha');
				$object->fk_user = GETPOST("fk_user",'int') > 0 ? GETPOST("fk_user",'int') : 0;
				$object->employee = GETPOST('employee','alphanothtml');

				$object->thm = GETPOST("thm",'alphanohtml') != '' ? GETPOST("thm",'alphanohtml') : '';
				$object->tjm = GETPOST("tjm",'alphanohtml') != '' ? GETPOST("tjm",'alphanohtml') : '';
				$object->salary = GETPOST("salary",'alphanohtml') != '' ? GETPOST("salary",'alphanohtml') : '';
				$object->salaryextra = GETPOST("salaryextra",'alphanohtml') != '' ? GETPOST("salaryextra",'alphanohtml') : '';
				$object->weeklyhours = GETPOST("weeklyhours",'alphanohtml') != '' ? GETPOST("weeklyhours",'alphanohtml') : '';

				$object->color = GETPOST("color",'alpha') != '' ? GETPOST("color",'alpha') : '';
				$dateemployment = dol_mktime(0, 0, 0, GETPOST('dateemploymentmonth','int'), GETPOST('dateemploymentday','int'), GETPOST('dateemploymentyear','int'));
				$object->dateemployment = $dateemployment;

				if (! empty($conf->multicompany->enabled))
				{
					if (! empty($_POST["superadmin"]))
					{
						$object->entity = 0;
					}
					else if (! empty($conf->global->MULTICOMPANY_TRANSVERSE_MODE))
					{
						$object->entity = 1; // all users in master entity
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -350,7 +350,7 @@
 				$object->accountancy_code = GETPOST("accountancy_code",'alpha');
 				$object->openid = GETPOST("openid",'alpha');
 				$object->fk_user = GETPOST("fk_user",'int') > 0 ? GETPOST("fk_user",'int') : 0;
-				$object->employee = GETPOST('employee','alphanothtml');
+				$object->employee = GETPOST('employee','int');
 
 				$object->thm = GETPOST("thm",'alphanohtml') != '' ? GETPOST("thm",'alphanohtml') : '';
 				$object->tjm = GETPOST("tjm",'alphanohtml') != '' ? GETPOST("tjm",'alphanohtml') : '';
```
