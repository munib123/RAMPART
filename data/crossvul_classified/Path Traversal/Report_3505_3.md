# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3505_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3505_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 4-44 of the vulnerable file.

# MantisBT is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# MantisBT is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @copyright Copyright (C) 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
 * @copyright Copyright (C) 2002 - 2011  MantisBT Team - mantisbt-dev@lists.sourceforge.net
 * @link http://www.mantisbt.org
 *	@package CoreAPI
 *	@subpackage BugGroupActionAPI
 */

/**
 * Print the top part for the bug action group page.
 */
function bug_group_action_print_top() {
	html_page_top();
}

/**
 * Print the bottom part for the bug action group page.
 */
function bug_group_action_print_bottom() {
	html_page_bottom();
}

/**
 * Print the list of selected issues and the legend for the status colors.
 *
 * @param $p_bug_ids_array   An array of issue ids.
 */
function bug_group_action_print_bug_list( $p_bug_ids_array ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,25 @@
  *	@package CoreAPI
  *	@subpackage BugGroupActionAPI
  */
+
+/**
+ * Initialise bug action group api
+ */
+function bug_group_action_init( $p_action ) {
+	$t_valid_actions = bug_group_action_get_commands( current_user_get_accessible_projects() );
+	$t_action = strtoupper( $p_action );
+
+	if ( !isset( $t_valid_actions[$t_action] ) && !isset ( $t_valid_actions['EXT_' . $t_action] ) ) {
+		trigger_error( ERROR_GENERIC, ERROR );
+	}
+
+	$t_include_file = config_get_global( 'absolute_path' ) . 'bug_actiongroup_' . $p_action . '_inc.php';
+	if ( !file_exists( $t_include_file ) ) {
+		trigger_error( ERROR_GENERIC, ERROR );
+	} else {
+		require_once( $t_include_file );
+	}
+}
 
 /**
  * Print the top part for the bug action group page.
@@ -94,7 +113,6 @@
  * @param $p_action   The custom action name without the "EXT_" prefix.
  */
 function bug_group_action_print_action_fields( $p_action ) {
-	require_once( dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'bug_actiongroup_' . $p_action . '_inc.php' );
 	$t_function_name = 'action_' . $p_action . '_print_fields';
 	$t_function_name();
 }
@@ -106,7 +124,6 @@
  * @param $p_action   The custom action name without the "EXT_" prefix.
  */
 function bug_group_action_print_title( $p_action ) {
-	require_once( dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'bug_actiongroup_' . $p_action . '_inc.php' );
 	$t_function_name = 'action_' . $p_action . '_print_title';
 	$t_function_name();
 }
@@ -121,7 +138,6 @@
  * @returns true|array true if action can be applied or array of ( bug_id => reason for failure to validate )
  */
 function bug_group_action_validate( $p_action, $p_bug_id ) {
-	require_once( dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'bug_actiongroup_' . $p_action . '_inc.php' );
 	$t_function_name = 'action_' . $p_action . '_validate';
 	return $t_function_name( $p_bug_id );
 }
@@ -136,7 +152,6 @@
  * @returns true|array Action can be applied., ( bug_id => reason for failure to process )
  */
 function bug_group_action_process( $p_action, $p_bug_id ) {
-	require_once( dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'bug_actiongroup_' . $p_action . '_inc.php' );
 	$t_function_name = 'action_' . $p_action . '_process';
 	return $t_function_name( $p_bug_id );
 }
```
