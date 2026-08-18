# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2067_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2067_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 13-55 of the vulnerable file.

#
# You should have received a copy of the GNU General Public License
# along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @package MantisBT
 * @copyright Copyright (C) 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
 * @copyright Copyright (C) 2002 - 2013  MantisBT Team - mantisbt-dev@lists.sourceforge.net
 * @link http://www.mantisbt.org
 */
/**
 * MantisBT Core API's
 */
require_once( dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'core.php' );

access_ensure_global_level( config_get_global( 'admin_site_threshold' ) );

# --------------------
function helper_table_row_count( $p_table ) {
	$t_table = $p_table;
	$query = "SELECT COUNT(*) FROM $t_table";
	$result = db_query_bound( $query );
	$t_users = db_result( $result );

	return $t_users;
}

# --------------------
function print_table_stats( $p_table_name ) {
	$t_count = helper_table_row_count( $p_table_name );
	echo "$p_table_name = $t_count records<br />";
}

echo '<html><head><title>MantisBT Database Statistics</title></head><body>';

echo '<h1>MantisBT Database Statistics</h1>';

foreach( db_get_table_list() as $t_table ) {
	if( db_table_exists( $t_table ) ) {
		print_table_stats( $t_table );
	}
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,11 +30,11 @@
 # --------------------
 function helper_table_row_count( $p_table ) {
 	$t_table = $p_table;
-	$query = "SELECT COUNT(*) FROM $t_table";
-	$result = db_query_bound( $query );
-	$t_users = db_result( $result );
+	$t_query = "SELECT COUNT(*) FROM $t_table";
+	$t_result = db_query_bound( $t_query );
+	$t_count = db_result( $t_result );
 
-	return $t_users;
+	return $t_count;
 }
 
 # --------------------
```
