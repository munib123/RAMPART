# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3506_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3506_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 819-859 of the vulnerable file.

}

function print_column_title_overdue( $p_sort, $p_dir, $p_columns_target = COLUMNS_TARGET_VIEW_PAGE ) {
	global $t_icon_path;
	echo '<td>';
	$t_overdue_text = lang_get( 'overdue' );
	$t_overdue_icon = '<img src="' . $t_icon_path . 'overdue.png" alt="' . $t_overdue_text . '" title="' . $t_overdue_text . '" />';
	print_view_bug_sort_link( $t_overdue_icon, 'due_date', $p_sort, $p_dir, $p_columns_target );
	print_sort_icon( $p_dir, $p_sort, 'due_date' );
	echo '</td>';
}

/**
 *
 * @param BugData $p_bug bug obect
 * @param int $p_columns_target: see COLUMNS_TARGET_* in constant_inc.php
 * @return null
 * @access public
 */
function print_column_selection( $p_bug, $p_columns_target = COLUMNS_TARGET_VIEW_PAGE ) {
	global $t_checkboxes_exist, $t_update_bug_threshold;

	echo '<td>';
	if( access_has_bug_level( $t_update_bug_threshold, $p_bug->id ) ) {
		$t_checkboxes_exist = true;
		printf( "<input type=\"checkbox\" name=\"bug_arr[]\" value=\"%d\" />", $p_bug->id );
	} else {
		echo "&#160;";
	}
	echo '</td>';
}

/**
 * Print column title for a specific custom column.
 * @param object Column object
 * @param string sort
 * @param string direction
 * @param int $p_columns_target: see COLUMNS_TARGET_* in constant_inc.php
 * @access public
 */
function print_column_title_plugin( $p_column, $p_column_object, $p_sort, $p_dir, $p_columns_target=COLUMNS_TARGET_VIEW_PAGE ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -836,11 +836,24 @@
  * @access public
  */
 function print_column_selection( $p_bug, $p_columns_target = COLUMNS_TARGET_VIEW_PAGE ) {
-	global $t_checkboxes_exist, $t_update_bug_threshold;
-
-	echo '<td>';
-	if( access_has_bug_level( $t_update_bug_threshold, $p_bug->id ) ) {
-		$t_checkboxes_exist = true;
+	global $g_checkboxes_exist;
+
+	echo '<td>';
+	if( access_has_any_project( config_get( 'report_bug_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		# !TODO: check if any other projects actually exist for the bug to be moved to
+		access_has_project_level( config_get( 'move_bug_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		# !TODO: factor in $g_auto_set_status_to_assigned == ON
+		access_has_project_level( config_get( 'update_bug_assign_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		access_has_project_level( config_get( 'update_bug_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		access_has_project_level( config_get( 'delete_bug_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		# !TODO: check to see if the bug actually has any different selectable workflow states
+		access_has_project_level( config_get( 'update_bug_status_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		access_has_project_level( config_get( 'set_bug_sticky_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		access_has_project_level( config_get( 'change_view_status_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		access_has_project_level( config_get( 'add_bugnote_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		access_has_project_level( config_get( 'tag_attach_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ||
+		access_has_project_level( config_get( 'roadmap_update_threshold', null, null, $p_bug->project_id ), $p_bug->project_id ) ) {
+		$g_checkboxes_exist = true;
 		printf( "<input type=\"checkbox\" name=\"bug_arr[]\" value=\"%d\" />", $p_bug->id );
 	} else {
 		echo "&#160;";
```
