# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3596_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3596_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 890-930 of the vulnerable file.


	if ( $p_bug_status == $p_wanted_status ) {
		# no change in state, allow the transition
		return true;
	}

	# workflow defined - find allowed states
	$t_allowed_states = $t_status_enum_workflow[$p_bug_status];

	return MantisEnum::hasValue( $t_allowed_states, $p_wanted_status );
}

/**
 * Copy a bug from one project to another. Also make copies of issue notes, attachments, history,
 * email notifications etc.
 * @todo Not managed FTP file upload
 * @param array p_bug_id integer representing bug id
 * @param int p_target_project_id
 * @param bool p_copy_custom_fields
 * @param bool p_copy_relationships
 * @return int representing the new bugid
 * @access public
 */
function bug_copy( $p_bug_id, $p_target_project_id = null, $p_copy_custom_fields = false, $p_copy_relationships = false, $p_copy_history = false, $p_copy_attachments = false, $p_copy_bugnotes = false, $p_copy_monitoring_users = false ) {
	global $g_db;

	$t_mantis_custom_field_string_table = db_get_table( 'custom_field_string' );
	$t_mantis_bug_file_table = db_get_table( 'bug_file' );
	$t_mantis_bugnote_table = db_get_table( 'bugnote' );
	$t_mantis_bugnote_text_table = db_get_table( 'bugnote_text' );
	$t_mantis_bug_history_table = db_get_table( 'bug_history' );
	$t_mantis_db = $g_db;

	$t_bug_id = db_prepare_int( $p_bug_id );
	$t_target_project_id = db_prepare_int( $p_target_project_id );

	$t_bug_data = bug_get( $t_bug_id, true );

	# retrieve the project id associated with the bug
	if(( $p_target_project_id == null ) || is_blank( $p_target_project_id ) ) {
		$t_target_project_id = $t_bug_data->project_id;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -907,6 +907,10 @@
  * @param int p_target_project_id
  * @param bool p_copy_custom_fields
  * @param bool p_copy_relationships
+ * @param bool p_copy_history
+ * @param bool p_copy_attachments
+ * @param bool p_copy_bugnotes
+ * @param bool p_copy_monitoring_users
  * @return int representing the new bugid
  * @access public
  */
@@ -1053,6 +1057,10 @@
 			db_query_bound( $query, Array( $t_bug_history['user_id'], $t_new_bug_id, $t_bug_history['date_modified'], $t_bug_history['field_name'], $t_bug_history['old_value'], $t_bug_history['new_value'], $t_bug_history['type'] ) );
 		}
 	}
+
+	# Create history entries to reflect the copy operation
+	history_log_event_special( $t_new_bug_id, BUG_CREATED_FROM, '', $t_bug_id );
+	history_log_event_special( $t_bug_id, BUG_CLONED_TO, '', $t_new_bug_id );
 
 	return $t_new_bug_id;
 }
```
