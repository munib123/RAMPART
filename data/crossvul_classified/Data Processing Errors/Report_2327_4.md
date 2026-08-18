# CrossVul Fix Pair: Data Processing Errors in php
**Pair ID:** 2327_4
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2327_4`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```php
Lines 2-42 of the vulnerable file.

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
#
# --------------------------------------------------------
# $Id$
# --------------------------------------------------------

require_once( 'core.php' );

auth_ensure_user_authenticated( );
helper_begin_long_process( );

$t_page_number = 1;
$t_per_page = -1;
$t_bug_count = null;
$t_page_count = null;

$t_nl = "\n";

# Get bug rows according to the current filter
$t_result = filter_get_bug_rows( $t_page_number, $t_per_page, $t_page_count, $t_bug_count );
if( $t_result === false ) {
	$t_result = array( );
}

$t_filename = "exported_issues.xml";

# Send headers to browser to activate mime loading
# Make sure that IE can download the attachments under https.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,8 @@
 # --------------------------------------------------------
 
 require_once( 'core.php' );
+
+access_ensure_project_level( plugin_config_get( 'export_threshold' ) );
 
 auth_ensure_user_authenticated( );
 helper_begin_long_process( );
```
