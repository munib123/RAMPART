# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3505_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3505_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 3-45 of the vulnerable file.


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
	 * @package MantisBT
	 * @copyright Copyright (C) 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
	 * @copyright Copyright (C) 2002 - 2011  MantisBT Team - mantisbt-dev@lists.sourceforge.net
	 * @link http://www.mantisbt.org
	 */
	 /**
	  * MantisBT Core API's
	  */
	require_once( 'core.php' );

	require_once( 'bug_group_action_api.php' );

	auth_ensure_user_authenticated();

	$f_action = gpc_get_string( 'action' );
	$f_bug_arr = gpc_get_int_array( 'bug_arr', array() );

	# redirect to view issues if nothing is selected
	if ( is_blank( $f_action ) || ( 0 == count( $f_bug_arr ) ) ) {
		print_header_redirect( 'view_all_bug_page.php' );
	}

  # redirect to view issues page if action doesn't have ext_* prefix.
  # This should only occur if this page is called directly.
	$t_external_action_prefix = 'EXT_';
	if ( strpos( $f_action, $t_external_action_prefix ) !== 0 ) {
		print_header_redirect( 'view_all_bug_page.php' );
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,33 +20,14 @@
 	 * @copyright Copyright (C) 2002 - 2011  MantisBT Team - mantisbt-dev@lists.sourceforge.net
 	 * @link http://www.mantisbt.org
 	 */
-	 /**
-	  * MantisBT Core API's
-	  */
+
 	require_once( 'core.php' );
-
 	require_once( 'bug_group_action_api.php' );
 
-	auth_ensure_user_authenticated();
+	$t_external_action = utf8_strtolower( utf8_substr( $f_action, utf8_strlen( $t_external_action_prefix ) ) );
+	$t_form_name = 'bug_actiongroup_' . $t_external_action;
 
-	$f_action = gpc_get_string( 'action' );
-	$f_bug_arr = gpc_get_int_array( 'bug_arr', array() );
-
-	# redirect to view issues if nothing is selected
-	if ( is_blank( $f_action ) || ( 0 == count( $f_bug_arr ) ) ) {
-		print_header_redirect( 'view_all_bug_page.php' );
-	}
-
-  # redirect to view issues page if action doesn't have ext_* prefix.
-  # This should only occur if this page is called directly.
-	$t_external_action_prefix = 'EXT_';
-	if ( strpos( $f_action, $t_external_action_prefix ) !== 0 ) {
-		print_header_redirect( 'view_all_bug_page.php' );
-  }
-
-	$t_external_action = utf8_strtolower( utf8_substr( $f_action, utf8_strlen( $t_external_action_prefix ) ) );
-	$t_form_fields_page = 'bug_actiongroup_' . $t_external_action . '_inc.php';
-	$t_form_name = 'bug_actiongroup_' . $t_external_action;
+	bug_group_action_init( $t_external_action );
 
 	bug_group_action_print_top();
 ?>
```
