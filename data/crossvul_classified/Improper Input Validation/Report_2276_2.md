# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2276_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2276_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 119-159 of the vulnerable file.

 */
function bugnote_is_user_reporter( $p_bugnote_id, $p_user_id ) {
	if( bugnote_get_field( $p_bugnote_id, 'reporter_id' ) == $p_user_id ) {
		return true;
	} else {
		return false;
	}
}

/**
 * Add a bugnote to a bug
 * return the ID of the new bugnote
 * @param int $p_bug_id bug id
 * @param string $p_bugnote_text bugnote text
 * @param string $p_time_tracking hh:mm string
 * @param bool $p_private whether bugnote is private
 * @param int $p_type bugnote type
 * @param string $p_attr
 * @param int $p_user_id user id
 * @param bool $p_send_email generate email?
 * @return false|int false or indicating bugnote id added
 * @access public
 */
function bugnote_add( $p_bug_id, $p_bugnote_text, $p_time_tracking = '0:00', $p_private = false, $p_type = 0, $p_attr = '', $p_user_id = null, $p_send_email = TRUE ) {
	$c_bug_id = db_prepare_int( $p_bug_id );
	$c_time_tracking = helper_duration_to_minutes( $p_time_tracking );
	$c_private = db_prepare_bool( $p_private );
	$c_type = db_prepare_int( $p_type );

	$t_bugnote_text_table = db_get_table( 'bugnote_text' );
	$t_bugnote_table = db_get_table( 'bugnote' );

	$t_time_tracking_enabled = config_get( 'time_tracking_enabled' );
	$t_time_tracking_without_note = config_get( 'time_tracking_without_note' );

	if( ON == $t_time_tracking_enabled && $c_time_tracking > 0 ) {
		if( is_blank( $p_bugnote_text ) && OFF == $t_time_tracking_without_note ) {
			error_parameters( lang_get( 'bugnote' ) );
			trigger_error( ERROR_EMPTY_FIELD, ERROR );
		}
		$c_type = TIME_TRACKING;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,14 +136,19 @@
  * @param string $p_attr
  * @param int $p_user_id user id
  * @param bool $p_send_email generate email?
+ * @param int $p_date_submitted date submitted (defaults to now())
+ * @param int $p_last_modified last modification date (defaults to now())
+ * @param bool $p_skip_bug_update skip bug last modification update (useful when importing bugs/bugnotes)
  * @return false|int false or indicating bugnote id added
  * @access public
  */
-function bugnote_add( $p_bug_id, $p_bugnote_text, $p_time_tracking = '0:00', $p_private = false, $p_type = 0, $p_attr = '', $p_user_id = null, $p_send_email = TRUE ) {
+function bugnote_add( $p_bug_id, $p_bugnote_text, $p_time_tracking = '0:00', $p_private = false, $p_type = 0, $p_attr = '', $p_user_id = null, $p_send_email = TRUE, $p_date_submitted = 0, $p_last_modified = 0, $p_skip_bug_update = FALSE ) {
 	$c_bug_id = db_prepare_int( $p_bug_id );
 	$c_time_tracking = helper_duration_to_minutes( $p_time_tracking );
 	$c_private = db_prepare_bool( $p_private );
 	$c_type = db_prepare_int( $p_type );
+	$c_date_submitted = $p_date_submitted <= 0 ? db_now() : db_prepare_int( $p_date_submitted );
+	$c_last_modified = $p_last_modified <= 0 ? db_now() : db_prepare_int( $p_last_modified );
 
 	$t_bugnote_text_table = db_get_table( 'bugnote_text' );
 	$t_bugnote_table = db_get_table( 'bugnote' );
@@ -181,7 +186,7 @@
 	}
 
 	# Check for private bugnotes.
-	if( $p_private && access_has_bug_level( config_get( 'set_view_status_threshold' ), $p_bug_id, $c_user_id ) ) {
+	if( $c_private && access_has_bug_level( config_get( 'set_view_status_threshold' ), $p_bug_id, $c_user_id ) ) {
 		$t_view_state = VS_PRIVATE;
 	} else {
 		$t_view_state = VS_PUBLIC;
@@ -192,13 +197,15 @@
 				(bug_id, reporter_id, bugnote_text_id, view_state, date_submitted, last_modified, note_type, note_attr, time_tracking )
 			VALUES
 				(" . db_param() . ', ' . db_param() . ',' . db_param() . ', ' . db_param() . ', ' . db_param() . ',' . db_param() . ', ' . db_param() . ', ' . db_param() . ', ' . db_param() . ' )';
-	db_query_bound( $query, Array( $c_bug_id, $c_user_id, $t_bugnote_text_id, $t_view_state, db_now(), db_now(), $c_type, $p_attr, $c_time_tracking ) );
+	db_query_bound( $query, Array( $c_bug_id, $c_user_id, $t_bugnote_text_id, $t_view_state, $c_date_submitted, $c_last_modified, $c_type, $p_attr, $c_time_tracking ) );
 
 	# get bugnote id
 	$t_bugnote_id = db_insert_id( $t_bugnote_table );
 
 	# update bug last updated
-	bug_update_date( $p_bug_id );
+	if ( !$p_skip_bug_update ) {
+		bug_update_date( $p_bug_id );
+	}
 
 	# log new bug
 	history_log_event_special( $p_bug_id, BUGNOTE_ADDED, bugnote_format_id( $t_bugnote_id ) );
```
