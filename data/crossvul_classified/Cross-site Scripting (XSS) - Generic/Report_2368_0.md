# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2368_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2368_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 13-53 of the vulnerable file.

#
# You should have received a copy of the GNU General Public License
# along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.
# This upgrade moves attachments from the database to the disk

/**
 * @package MantisBT
 * @copyright Copyright (C) 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
 * @copyright Copyright (C) 2002 - 2014  MantisBT Team - mantisbt-dev@lists.sourceforge.net
 * @link http://www.mantisbt.org
 */
/**
 * MantisBT Core API's
 */
require_once( dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'core.php' );

access_ensure_global_level( config_get_global( 'admin_site_threshold' ) );

$f_source_field_id = gpc_get_int( 'source_id' );
$f_dest_field = gpc_get( 'dest_id' );
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title> MantisBT Administration - Copy Custom Fields to Built-in </title>
<link rel="stylesheet" type="text/css" href="admin.css" />
</head>
<body>

<table width="100%" border="0" cellspacing="0" cellpadding="0" bgcolor="#ffffff">
	<tr class="top-bar">
		<td class="links">
			[ <a href="system_utils.php">Back to System Utilities</a> ]
			[ <a href="copy_field.php?source_id=<?php echo $f_source_field_id?>&amp;dest_id=<?php echo $f_dest_field?>">Refresh view</a> ]
		</td>
		<td class="title">
			MantisBT Administration - Copy Custom Fields to Built-in
		</td>
	</tr>
</table>
<br /><br />
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,18 @@
 
 $f_source_field_id = gpc_get_int( 'source_id' );
 $f_dest_field = gpc_get( 'dest_id' );
+
+# checks on validity
+$t_valid_fields = array(
+	'fixed_in_version',
+);
+if( !in_array( $f_dest_field, $t_valid_fields ) ) {
+	echo '<html><body>';
+	echo '<p>Invalid destination field (' . string_attribute($f_dest_field) . ') specified.</p>';
+	echo '</body></html>';
+	exit;
+}
+
 ?>
 <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
 <html>
@@ -53,15 +65,6 @@
 <br /><br />
 
 <?php
-# checks on validity
-$t_valid_fields = array(
-	'fixed_in_version',
-);
-if( !in_array( $f_dest_field, $t_valid_fields ) ) {
-	echo '<p>Invalid destination field (' . $f_dest_field . ') specified.</p>';
-	echo '</body></html>';
-	exit;
-}
 
 # @@@ check that source and destination are compatible
 
```
