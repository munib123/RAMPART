# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2388_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2388_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 338-378 of the vulnerable file.

				print_test_result( GOOD );
			}
		} else {
			print_test_result( BAD, false, 'Database user doesn\'t have access to the database ( ' . db_error_msg() . ' )' );
		}
		?>
</tr>

<?php
	}
	if( $t_db_open ) {
		?>
<!-- display database version -->
<tr>
	<td bgcolor="#ffffff">
		Checking Database Server Version
		<?php
		# due to a bug in ADODB, this call prompts warnings, hence the @
		# the check only works on mysql if the database is open
		$t_version_info = @$g_db->ServerInfo();
		echo '<br /> Running ' . $f_db_type . ' version ' . $t_version_info['description'];
		?>
	</td>
	<?php
		$t_warning = '';
		$t_error = '';
		switch( $f_db_type ) {
			case 'mysql':
			case 'mysqli':
				if( version_compare( $t_version_info['version'], '4.1.0', '<' ) ) {
					$t_error = 'MySQL 4.1.0 or later is required for installation.';
				}
				break;
			case 'mssql':
			case 'mssqlnative':
				if( version_compare( $t_version_info['version'], '9.0.0', '<' ) ) {
					$t_error = 'SQL Server 2005 or later is required for installation.';
				}
				break;
			case 'pgsql':
			case 'db2':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -355,7 +355,7 @@
 		# due to a bug in ADODB, this call prompts warnings, hence the @
 		# the check only works on mysql if the database is open
 		$t_version_info = @$g_db->ServerInfo();
-		echo '<br /> Running ' . $f_db_type . ' version ' . $t_version_info['description'];
+		echo '<br /> Running ' . string_attribute( $f_db_type ) . ' version ' . $t_version_info['description'];
 		?>
 	</td>
 	<?php
@@ -444,7 +444,7 @@
 		Hostname (for Database Server)
 	</td>
 	<td>
-		<input name="hostname" type="textbox" value="<?php echo $f_hostname?>"></input>
+		<input name="hostname" type="textbox" value="<?php echo string_attribute( $f_hostname ) ?>"></input>
 	</td>
 </tr>
 <?php
@@ -456,7 +456,7 @@
 		Username (for Database)
 	</td>
 	<td>
-		<input name="db_username" type="textbox" value="<?php echo $f_db_username?>"></input>
+		<input name="db_username" type="textbox" value="<?php echo string_attribute( $f_db_username ) ?>"></input>
 	</td>
 </tr>
 <?php
@@ -480,7 +480,7 @@
 		Database name (for Database)
 	</td>
 	<td>
-		<input name="database_name" type="textbox" value="<?php echo $f_database_name?>"></input>
+		<input name="database_name" type="textbox" value="<?php echo string_attribute( $f_database_name ) ?>"></input>
 	</td>
 </tr>
 <?php
@@ -491,7 +491,7 @@
 		Admin Username (to <?php echo( !$g_database_upgrade ) ? 'create Database' : 'update Database'?> if required)
 	</td>
 	<td>
-		<input name="admin_username" type="textbox" value="<?php echo $f_admin_username?>"></input>
+		<input name="admin_username" type="textbox" value="<?php echo string_attribute( $f_admin_username ) ?>"></input>
 	</td>
 </tr>
 
@@ -500,7 +500,7 @@
 		Admin Password (to <?php echo( !$g_database_upgrade ) ? 'create Database' : 'update Database'?> if required)
 	</td>
 	<td>
-		<input name="admin_password" type="password" value="<?php echo $f_admin_password?>"></input>
+		<input name="admin_password" type="password" value="<?php echo string_attribute( $f_admin_password ) ?>"></input>
 	</td>
 </tr>
 
@@ -754,13 +754,13 @@
 	/** @todo to be written */
 	// must post data gathered to preserve it
 	?>
-		<input name="hostname" type="hidden" value="<?php echo $f_hostname?>"></input>
-		<input name="db_type" type="hidden" value="<?php echo $f_db_type?>"></input>
-		<input name="database_name" type="hidden" value="<?php echo $f_database_name?>"></input>
-		<input name="db_username" type="hidden" value="<?php echo $f_db_username?>"></input>
-		<input name="db_password" type="hidden" value="<?php echo $f_db_password?>"></input>
-		<input name="admin_username" type="hidden" value="<?php echo $f_admin_username?>"></input>
-		<input name="admin_password" type="hidden" value="<?php echo $f_admin_password?>"></input>
+		<input name="hostname" type="hidden" value="<?php echo string_attribute( $f_hostname ) ?>"></input>
+		<input name="db_type" type="hidden" value="<?php echo string_attribute( $f_db_type ) ?>"></input>
+		<input name="database_name" type="hidden" value="<?php echo string_attribute( $f_database_name ) ?>"></input>
+		<input name="db_username" type="hidden" value="<?php echo string_attribute( $f_db_username ) ?>"></input>
+		<input name="db_password" type="hidden" value="<?php echo string_attribute( $f_db_password ) ?>"></input>
+		<input name="admin_username" type="hidden" value="<?php echo string_attribute( $f_admin_username ) ?>"></input>
+		<input name="admin_password" type="hidden" value="<?php echo string_attribute( $f_admin_password ) ?>"></input>
 		<input name="log_queries" type="hidden" value="<?php echo( $f_log_queries ? 1 : 0 )?>"></input>
 		<input name="db_exists" type="hidden" value="<?php echo( $f_db_exists ? 1 : 0 )?>"></input>
 <?php
@@ -986,14 +986,14 @@
 <tr>
 	<td bgcolor="#ffffff">Please correct failed checks</td>
 	<td bgcolor="#ffffff">
-		<input name="install" type="hidden" value="<?php echo $t_install_state?>"></input>
-		<input name="hostname" type="hidden" value="<?php echo $f_hostname?>"></input>
-		<input name="db_type" type="hidden" value="<?php echo $f_db_type?>"></input>
-		<input name="database_name" type="hidden" value="<?php echo $f_database_name?>"></input>
-		<input name="db_username" type="hidden" value="<?php echo $f_db_username?>"></input>
-		<input name="db_password" type="hidden" value="<?php echo $f_db_password?>"></input>
-		<input name="admin_username" type="hidden" value="<?php echo $f_admin_username?>"></input>
-		<input name="admin_password" type="hidden" value="<?php echo $f_admin_password?>"></input>
+		<input name="install" type="hidden" value="<?php echo $t_install_state ?>"></input>
+		<input name="hostname" type="hidden" value="<?php echo string_attribute( $f_hostname ) ?>"></input>
+		<input name="db_type" type="hidden" value="<?php echo string_attribute( $f_db_type ) ?>"></input>
+		<input name="database_name" type="hidden" value="<?php echo string_attribute( $f_database_name ) ?>"></input>
+		<input name="db_username" type="hidden" value="<?php echo string_attribute( $f_db_username ) ?>"></input>
+		<input name="db_password" type="hidden" value="<?php echo string_attribute( $f_db_password ) ?>"></input>
+		<input name="admin_username" type="hidden" value="<?php echo string_attribute( $f_admin_username ) ?>"></input>
+		<input name="admin_password" type="hidden" value="<?php echo string_attribute( $f_admin_password ) ?>"></input>
 		<input name="log_queries" type="hidden" value="<?php echo( $f_log_queries ? 1 : 0 )?>"></input>
 		<input name="db_exists" type="hidden" value="<?php echo( $f_db_exists ? 1 : 0 )?>"></input>
 		<input name="retry" type="submit" class="button" value="Retry"></input>
```
