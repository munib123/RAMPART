# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3506_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3506_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 30-70 of the vulnerable file.

/**
 * requires string_api
 */
require_once( 'string_api.php' );
/**
 * requires prepare_api
 */
require_once( 'prepare_api.php' );
/**
 * requires profile_api
 */
require_once( 'profile_api.php' );
/**
 * requires last_visited_api
 */
require_once( 'last_visited_api.php' );
/**
 * requires file_api
 */
require_once( 'file_api.php' );

# --------------------
# Print the headers to cause the page to redirect to $p_url
# If $p_die is true (default), terminate the execution of the script
#  immediately
# If we have handled any errors on this page and the 'stop_on_errors' config
#  option is turned on, return false and don't redirect.
# $p_sanitize - true/false - true in the case where the URL is extracted from GET/POST or untrusted source.
# This would be false if the URL is trusted (e.g. read from config_inc.php).
#
# @param string The page to redirect: has to be a relative path
# @param boolean if true, stop the script after redirecting
# @param boolean apply string_sanitize_url to passed url
# @return boolean
function print_header_redirect( $p_url, $p_die = true, $p_sanitize = false, $p_absolute = false ) {
	$t_use_iis = config_get( 'use_iis' );

	if( ON == config_get_global( 'stop_on_errors' ) && error_handled() ) {
		return false;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,8 @@
  */
 require_once( 'file_api.php' );
 
+require_once( 'bug_group_action_api.php' );
+
 # --------------------
 # Print the headers to cause the page to redirect to $p_url
 # If $p_die is true (default), terminate the execution of the script
@@ -945,68 +947,16 @@
 	}
 }
 
-# @@@ preliminary support for multiple bug actions.
-function print_all_bug_action_option_list() {
-	$commands = array(
-		'MOVE' => lang_get( 'actiongroup_menu_move' ),
-		'COPY' => lang_get( 'actiongroup_menu_copy' ),
-		'ASSIGN' => lang_get( 'actiongroup_menu_assign' ),
-		'CLOSE' => lang_get( 'actiongroup_menu_close' ),
-		'DELETE' => lang_get( 'actiongroup_menu_delete' ),
-		'RESOLVE' => lang_get( 'actiongroup_menu_resolve' ),
-		'SET_STICKY' => lang_get( 'actiongroup_menu_set_sticky' ),
-		'UP_PRIOR' => lang_get( 'actiongroup_menu_update_priority' ),
-		'EXT_UPDATE_SEVERITY' => lang_get( 'actiongroup_menu_update_severity' ),
-		'UP_STATUS' => lang_get( 'actiongroup_menu_update_status' ),
-		'UP_CATEGORY' => lang_get( 'actiongroup_menu_update_category' ),
-		'VIEW_STATUS' => lang_get( 'actiongroup_menu_update_view_status' ),
-		'EXT_UPDATE_PRODUCT_BUILD' => lang_get( 'actiongroup_menu_update_product_build' ),
-		'EXT_ADD_NOTE' => lang_get( 'actiongroup_menu_add_note' ),
-		'EXT_ATTACH_TAGS' => lang_get( 'actiongroup_menu_attach_tags' ),
-	);
-
-	$t_project_id = helper_get_current_project();
-
-	if( ALL_PROJECTS != $t_project_id ) {
-		$t_user_id = auth_get_current_user_id();
-
-		if( access_has_project_level( config_get( 'update_bug_threshold' ), $t_project_id ) ) {
-			$commands['UP_FIXED_IN_VERSION'] = lang_get( 'actiongroup_menu_update_fixed_in_version' );
-		}
-
-		if( access_has_project_level( config_get( 'roadmap_update_threshold' ), $t_project_id ) ) {
-			$commands['UP_TARGET_VERSION'] = lang_get( 'actiongroup_menu_update_target_version' );
-		}
-
-		$t_custom_field_ids = custom_field_get_linked_ids( $t_project_id );
-
-		foreach( $t_custom_field_ids as $t_custom_field_id ) {
-			# if user has not access right to modify the field, then there is no
-			# point in showing it.
-			if( !custom_field_has_write_access_to_project( $t_custom_field_id, $t_project_id, $t_user_id ) ) {
-				continue;
-			}
-
-			$t_custom_field_def = custom_field_get_definition( $t_custom_field_id );
-			$t_command_id = 'custom_field_' . $t_custom_field_id;
-			$t_command_caption = sprintf( lang_get( 'actiongroup_menu_update_field' ), lang_get_defaulted( $t_custom_field_def['name'] ) );
-			$commands[$t_command_id] = string_display( $t_command_caption );
-		}
-	}
-
-	$t_custom_group_actions = config_get( 'custom_group_actions' );
-
-	foreach( $t_custom_group_actions as $t_custom_group_action ) {
-		# use label if provided to get the localized text, otherwise fallback to action name.
-		if( isset( $t_custom_group_action['label'] ) ) {
-			$commands[$t_custom_group_action['action']] = lang_get_defaulted( $t_custom_group_action['label'] );
-		} else {
-			$commands[$t_custom_group_action['action']] = lang_get_defaulted( $t_custom_group_action['action'] );
-		}
-	}
-
-	while( list( $key, $val ) = each( $commands ) ) {
-		echo '<option value="' . $key . '">' . $val . '</option>';
+/**
+ * Print a dropdown list of all bug actions available to a user for a specified
+ * set of projects.
+ * @param array $p_projects An array containing one or more project IDs
+ * @return null
+ */
+function print_all_bug_action_option_list( $p_project_ids = null ) {
+	$t_commands = bug_group_action_get_commands( $p_project_ids);
+	while( list( $t_action_id, $t_action_label ) = each( $t_commands ) ) {
+		echo '<option value="' . $t_action_id . '">' . $t_action_label . '</option>';
 	}
 }
 
```
