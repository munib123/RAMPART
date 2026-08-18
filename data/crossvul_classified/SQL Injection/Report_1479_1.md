# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1479_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1479_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 112-152 of the vulnerable file.

							'updates_from.01.00.01.sql',
							'updates_from.01.00.02.sql',
							'updates_from.01.00.03.sql',
							'updates_from.01.01.90.sql',
							'updates_from.01.01.91.sql',
							'updates_from.01.01.92.sql',
							'updates_from.01.02.00.sql',
							'updates_from.01.02.01.sql',
							'updates_from.01.02.02.sql',
							'updates_from.01.03.00.sql',
							'updates_from.01.03.01.sql',
							'updates_from.01.04.00.sql',
							'updates_from.01.04.01.sql',
							'updates_from.01.04.02.sql',
							'updates_from.01.04.03.sql',
							'updates_from.01.04.04.sql',
							'updates_from.01.04.05.sql',
							'updates_from.01.04.06.sql',
							'updates_from.01.05.00.sql',
							'updates_from.01.05.01.sql',
							'updates_from.01.06.00.sql');

	/**
	* Konstruktor. Catch all globals
	*/
	function setup()
	{
		$this -> catch_globals();
		$this -> version['prior'] = '01';
		$this -> version['minor'] = '06';
		$this -> version['fix']   = '01';
		$this -> version_text = $this -> version['prior'];
		$this -> version_text .= '.';
		$this -> version_text .= $this -> version['minor'];
		$this -> version_text .= '.';
		$this -> version_text .= $this -> version['fix'];
		//manipulate some actions if user chose updat
		if ($this -> globals['mode'] == 'update') {
			//seperate update finish screen
			if ($this -> globals['action'] == 'enter_email') $this -> globals['action'] = 'screen_execute_update_and_finish';
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,7 +129,8 @@
 							'updates_from.01.04.06.sql',
 							'updates_from.01.05.00.sql',
 							'updates_from.01.05.01.sql',
-							'updates_from.01.06.00.sql');
+							'updates_from.01.06.00.sql',
+							'updates_from.01.06.01.sql');
 
 	/**
 	* Konstruktor. Catch all globals
@@ -139,7 +140,7 @@
 		$this -> catch_globals();
 		$this -> version['prior'] = '01';
 		$this -> version['minor'] = '06';
-		$this -> version['fix']   = '01';
+		$this -> version['fix']   = '02';
 		$this -> version_text = $this -> version['prior'];
 		$this -> version_text .= '.';
 		$this -> version_text .= $this -> version['minor'];
```
