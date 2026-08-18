# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2067_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2067_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 84-124 of the vulnerable file.


	// walk through all issues and grab their status for 'now'
	$t_marker[$t_ptr] = time();
	foreach ($rows as $t_row) {
	    if ( isset( $t_data[$t_ptr][$t_row->status] ) ) {
            $t_data[$t_ptr][$t_row->status] ++;
	    } else {
            $t_data[$t_ptr][$t_row->status] = 1;
            $t_view_status[$t_row->status] =
                isset($t_status_arr[$t_row->status]) ? $t_status_arr[$t_row->status] : '@'.$t_row->status.'@';
        }
        $t_bug[] = $t_row->id;
	}

    // get the history for these bugs over the interval required to offset the data
    // type = 0 and field=status are status changes
    // type = 1 are new bugs
    $t_select = 'SELECT bug_id, type, old_value, new_value, date_modified FROM '.$t_bug_hist_table.
        ' WHERE bug_id in ('.implode(',', $t_bug).
        ') and ( (type='.NORMAL_TYPE.' and field_name=\'status\')
            or type='.NEW_BUG.' ) and date_modified >= \''. $t_start .'\''.
        ' order by date_modified DESC';
    $t_result = db_query( $t_select );
	$t_row = db_fetch_array( $t_result );

	for ($t_now = time() - $t_incr; $t_now >= $t_start; $t_now -= $t_incr) {
	    // walk through the data points and use the data retrieved to update counts
	    while( ( $t_row !== false ) && ( $t_row['date_modified'] >= $t_now ) ) {
	        switch ($t_row['type']) {
    	        case 0: // updated bug
        	        if ( isset( $t_data[$t_ptr][$t_row['new_value']] ) ) {
                        if ( $t_data[$t_ptr][$t_row['new_value']] > 0 )
                            $t_data[$t_ptr][$t_row['new_value']] --;
        	        } else {
                        $t_data[$t_ptr][$t_row['new_value']] = 0;
                        $t_view_status[$t_row['new_value']] =
                            isset($t_status_arr[$t_row['new_value']]) ? $t_status_arr[$t_row['new_value']] : '@'.$t_row['new_value'].'@';
                    }
        	        if ( isset( $t_data[$t_ptr][$t_row['old_value']] ) ) {
                        $t_data[$t_ptr][$t_row['old_value']] ++;
        	        } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,9 +101,9 @@
     $t_select = 'SELECT bug_id, type, old_value, new_value, date_modified FROM '.$t_bug_hist_table.
         ' WHERE bug_id in ('.implode(',', $t_bug).
         ') and ( (type='.NORMAL_TYPE.' and field_name=\'status\')
-            or type='.NEW_BUG.' ) and date_modified >= \''. $t_start .'\''.
+	or type='.NEW_BUG.' ) and date_modified >= ' . db_param() .
         ' order by date_modified DESC';
-    $t_result = db_query( $t_select );
+	$t_result = db_query_bound( $t_select, array( $t_start ) );
 	$t_row = db_fetch_array( $t_result );
 
 	for ($t_now = time() - $t_incr; $t_now >= $t_start; $t_now -= $t_incr) {
```
