# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2067_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2067_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 88-128 of the vulnerable file.

            $t_cat = 'none';
	    if ( !access_compare_level( $t_row->status, $t_resolved ) ) {
	        if (in_array($t_cat, $t_category)) {
                $t_data[$t_ptr][$t_cat] ++;
            } else {
                $t_data[$t_ptr][$t_cat] = 1;
                $t_category[] = $t_cat;
            }
        }
        $t_bug[] = $t_row->id;
        $t_bug_cat[$t_row->id] = $t_cat;
	}

    // get the history for these bugs over the interval required to offset the data
    // type = 0 and field=status are status changes
    // type = 1 are new bugs
    $t_select = 'SELECT bug_id, type, field_name, old_value, new_value, date_modified FROM '.$t_bug_hist_table.
        ' WHERE bug_id in ('.implode(',', $t_bug).') and '.
            '( (type='.NORMAL_TYPE.' and field_name=\'category\') or '.
                '(type='.NORMAL_TYPE.' and field_name=\'status\') or type='.NEW_BUG.' ) and '.
                'date_modified >= \''. $t_start .'\''.
            ' order by date_modified DESC';
    $t_result = db_query( $t_select );
	$row = db_fetch_array( $t_result );

	for ($t_now = time() - $t_incr; $t_now >= $t_start; $t_now -= $t_incr) {
	    // walk through the data points and use the data retrieved to update counts
	    while( ( $row !== false ) && ( $row['date_modified'] >= $t_now ) ) {
	        switch ($row['type']) {
    	        case 0: // updated bug
    	            if ($row['field_name'] == 'category') {
	                    $t_cat = $row['new_value'];
            	        if ($t_cat == '')
            	            $t_cat = 'none';
            	        if (in_array($t_cat, $t_category)) {
                            $t_data[$t_ptr][$t_cat] --;
                        } else {
                            $t_data[$t_ptr][$t_cat] = 0;
                            $t_category[] = $t_cat;
                        }
	                    $t_cat = $row['old_value'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,9 +105,9 @@
         ' WHERE bug_id in ('.implode(',', $t_bug).') and '.
             '( (type='.NORMAL_TYPE.' and field_name=\'category\') or '.
                 '(type='.NORMAL_TYPE.' and field_name=\'status\') or type='.NEW_BUG.' ) and '.
-                'date_modified >= \''. $t_start .'\''.
+		'date_modified >= ' . db_param() .
             ' order by date_modified DESC';
-    $t_result = db_query( $t_select );
+	$t_result = db_query_bound( $t_select, array( $t_start ) );
 	$row = db_fetch_array( $t_result );
 
 	for ($t_now = time() - $t_incr; $t_now >= $t_start; $t_now -= $t_incr) {
```
