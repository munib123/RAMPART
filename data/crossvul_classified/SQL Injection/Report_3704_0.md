# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3704_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3704_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 61-101 of the vulnerable file.

			{ 
				// OUTBOX
				$filter = 'message.message_type = 2';
			}
			else
			{
				// INBOX
				$type = "1";
				$filter = 'message.message_type = 1';
			}
		}
		else
		{
			$type = "1";
			$filter = 'message.message_type = 1';
		}
        
		// Do we have a reporter ID?
		if (isset($_GET['rid']) AND !empty($_GET['rid']))
		{
			$filter .= ' AND message.reporter_id=\''.$_GET['rid'].'\'';
		}
        
		// ALL / Trusted / Spam
		$level = '0';
		if (isset($_GET['level']) AND !empty($_GET['level']))
		{
			$level = $_GET['level'];
			if ($level == 4)
			{
				$filter .= " AND ( ".$table_prefix."reporter.level_id = '4' OR "
				    . $table_prefix."reporter.level_id = '5' ) "
				    . "AND ( ".$table_prefix."message.message_level != '99' ) ";
			}
			elseif ($level == 2)
			{
				$filter .= " AND ( ".$table_prefix."message.message_level = '99' ) ";
			}
		}

		// Check, has the form been submitted?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,7 @@
 		// Do we have a reporter ID?
 		if (isset($_GET['rid']) AND !empty($_GET['rid']))
 		{
-			$filter .= ' AND message.reporter_id=\''.$_GET['rid'].'\'';
+			$filter .= ' AND message.reporter_id=\''.intval($_GET['rid']).'\'';
 		}
         
 		// ALL / Trusted / Spam
```
