# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3597_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3597_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1020-1060 of the vulnerable file.

						   			" . db_param() . ",
						   			" . db_param() . ",
						   			" . db_param() . ')';
			db_query_bound( $query2, Array( $t_new_bug_id, $t_bug_note['reporter_id'], $t_bugnote_text_insert_id, $t_bug_note['view_state'], $t_bug_note['date_submitted'], $t_bug_note['last_modified'] ) );
		}
	}

	# Copy attachments
	if( $p_copy_attachments ) {
	    file_copy_attachments( $t_bug_id , $t_new_bug_id );
	}

	# Copy users monitoring bug
	if( $p_copy_monitoring_users ) {
		bug_monitor_copy( $t_bug_id, $t_new_bug_id );
	}

	# COPY HISTORY
	history_delete( $t_new_bug_id );	# should history only be deleted inside the if statement below?
	if( $p_copy_history ) {
		$query = "SELECT *
					  FROM $t_mantis_bug_history_table
					  WHERE bug_id = " . db_param();
		$result = db_query_bound( $query, Array( $t_bug_id ) );
		$t_count = db_num_rows( $result );

		for( $i = 0;$i < $t_count;$i++ ) {
			$t_bug_history = db_fetch_array( $result );
			$query = "INSERT INTO $t_mantis_bug_history_table
						  ( user_id, bug_id, date_modified, field_name, old_value, new_value, type )
						  VALUES ( " . db_param() . ",
						  		   " . db_param() . ",
						  		   " . db_param() . ",
						  		   " . db_param() . ",
						  		   " . db_param() . ",
						  		   " . db_param() . ",
						  		   " . db_param() . " );";
			db_query_bound( $query, Array( $t_bug_history['user_id'], $t_new_bug_id, $t_bug_history['date_modified'], $t_bug_history['field_name'], $t_bug_history['old_value'], $t_bug_history['new_value'], $t_bug_history['type'] ) );
		}
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1037,6 +1037,8 @@
 	# COPY HISTORY
 	history_delete( $t_new_bug_id );	# should history only be deleted inside the if statement below?
 	if( $p_copy_history ) {
+		# @todo problem with this code: the generated history trail is incorrect because the note IDs are those of the original bug, not the copied ones
+		# @todo actually, does it even make sense to copy the history ?
 		$query = "SELECT *
 					  FROM $t_mantis_bug_history_table
 					  WHERE bug_id = " . db_param();
@@ -1056,6 +1058,9 @@
 						  		   " . db_param() . " );";
 			db_query_bound( $query, Array( $t_bug_history['user_id'], $t_new_bug_id, $t_bug_history['date_modified'], $t_bug_history['field_name'], $t_bug_history['old_value'], $t_bug_history['new_value'], $t_bug_history['type'] ) );
 		}
+	} else {
+		# Create a "New Issue" history entry
+		history_log_event_special( $t_new_bug_id, NEW_BUG );
 	}
 
 	# Create history entries to reflect the copy operation
```
