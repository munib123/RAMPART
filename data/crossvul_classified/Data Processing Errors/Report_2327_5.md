# CrossVul Fix Pair: Data Processing Errors in php
**Pair ID:** 2327_5
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2327_5`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php
# MantisBT - a php based bugtracking system
# Copyright (C) 2002 - 2014  MantisBT Team - mantisbt-dev@lists.sourceforge.net
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

auth_reauthenticate( );

html_page_top( plugin_lang_get( 'import' ) );

$t_this_page = plugin_page('import'); //FIXME with plugins this does not work...
print_manage_menu( $t_this_page );

$t_max_file_size = (int)min(
	ini_get_number( 'upload_max_filesize' ),
	ini_get_number( 'post_max_size' ),
	config_get( 'max_file_size' )
);

// We need a project to import into
$t_project_id = helper_get_current_project( );
if( ALL_PROJECTS == $t_project_id ) {
	print_header_redirect( "login_select_proj_page.php?ref=$t_this_page" );
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,8 @@
 #
 # You should have received a copy of the GNU General Public License
 # along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.
+
+access_ensure_project_level( plugin_config_get( 'import_threshold' ) );
 
 auth_reauthenticate( );
 
```
