# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3701_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3701_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 546-586 of the vulnerable file.

			if (isset($_GET['s']) AND isset($_GET['e']))
			{
				$query = 'SELECT id FROM '.$this->table_prefix.'incident '
				    . 'WHERE incident_date >= "'.date("Y-m-d H:i:s", $_GET['s']).'" '
				    . 'AND incident_date <= "'.date('Y-m-d H:i:s', $_GET['e']).'"'
				    . $incident_id_in;

				$incident_id_in = $this->_exec_timeline_data_query($db, $query);

				if (empty($incident_id_in))
				{
					$incident_id_in = ' AND 3 = 4';
				}
			}


			// Apply media type filters
			if (isset($_GET['m']) AND intval($_GET['m']) > 0)
			{
				$query = "SELECT incident_id AS id FROM ".$this->table_prefix."media "
				    . "WHERE media_type = ".$_GET['m']
				    . $incident_id_in;

				$incident_id_in = $this->_exec_timeline_data_query($db, $query);

				if (empty($incident_id_in))
				{
					$incident_id_in = ' AND 3 = 4';
				}
			}
		}

		// Fetch the timeline data
		$query = 'SELECT UNIX_TIMESTAMP('.$select_date_text.') AS time, COUNT(id) AS number '
		    . 'FROM '.$this->table_prefix.'incident '
		    . 'WHERE incident_active = 1 '.$incident_id_in.' '
		    . 'GROUP BY '.$groupby_date_text;
		
		foreach ($db->query($query) as $items)
		{
			array_push($graph_data[0]['data'],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -563,7 +563,7 @@
 			if (isset($_GET['m']) AND intval($_GET['m']) > 0)
 			{
 				$query = "SELECT incident_id AS id FROM ".$this->table_prefix."media "
-				    . "WHERE media_type = ".$_GET['m']
+				    . "WHERE media_type = ".intval($_GET['m'])
 				    . $incident_id_in;
 
 				$incident_id_in = $this->_exec_timeline_data_query($db, $query);
```
