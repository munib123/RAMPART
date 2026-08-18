# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3506_5
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3506_5`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 38-78 of the vulnerable file.

	 */
	require_once( 'date_api.php' );
	/**
	 * requires icon_api
	 */
	require_once( 'icon_api.php' );
	/**
	 * requires columns_api
	 */
	require_once( 'columns_api.php' );

	$t_filter = current_user_get_bug_filter();
	# NOTE: this check might be better placed in current_user_get_bug_filter()
	if ( $t_filter === false ) {
		$t_filter = filter_get_default();
	}

	list( $t_sort, ) = explode( ',', $t_filter['sort'] );
	list( $t_dir, ) = explode( ',', $t_filter['dir'] );

	$t_checkboxes_exist = false;

	$t_icon_path = config_get( 'icon_path' );
	$t_update_bug_threshold = config_get( 'update_bug_threshold' );

	# Improve performance by caching category data in one pass
	if ( helper_get_current_project() > 0 ) {
		category_get_all_rows( helper_get_current_project() );
	} else {
		$t_categories = array();
		foreach ($rows as $t_row) {
			$t_categories[] = $t_row->category_id;
		}
		category_cache_array_rows( array_unique( $t_categories ) );
	}
	$t_columns = helper_get_columns_to_view( COLUMNS_TARGET_VIEW_PAGE );

	$col_count = count( $t_columns );

	$t_filter_position = config_get( 'filter_position' );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,10 +55,9 @@
 	list( $t_sort, ) = explode( ',', $t_filter['sort'] );
 	list( $t_dir, ) = explode( ',', $t_filter['dir'] );
 
-	$t_checkboxes_exist = false;
+	$g_checkboxes_exist = false;
 
 	$t_icon_path = config_get( 'icon_path' );
-	$t_update_bug_threshold = config_get( 'update_bug_threshold' );
 
 	# Improve performance by caching category data in one pass
 	if ( helper_get_current_project() > 0 ) {
@@ -226,14 +225,14 @@
 		<td class="left" colspan="<?php echo $col_count; ?>">
 			<span class="floatleft">
 <?php
-		if ( $t_checkboxes_exist && ON == config_get( 'use_javascript' ) ) {
+		if ( $g_checkboxes_exist && ON == config_get( 'use_javascript' ) ) {
 			echo "<input type=\"checkbox\" name=\"all_bugs\" value=\"all\" onclick=\"checkall('bug_action', this.form.all_bugs.checked)\" /><span class=\"small\">" . lang_get( 'select_all' ) . '</span>';
 		}
 
-		if ( $t_checkboxes_exist ) {
+		if ( $g_checkboxes_exist ) {
 ?>
 			<select name="action">
-				<?php print_all_bug_action_option_list() ?>
+				<?php print_all_bug_action_option_list( $t_unique_project_ids ) ?>
 			</select>
 			<input type="submit" class="button" value="<?php echo lang_get( 'ok' ); ?>" />
 <?php
```
