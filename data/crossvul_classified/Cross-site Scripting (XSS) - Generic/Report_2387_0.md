# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2387_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2387_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 441-481 of the vulnerable file.

					print_test_result( BAD, true, 'set schema failed: ' . $g_db->errorMsg() );
				}
			} else {
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
		echo '<br /> Running ' . $f_db_type . ' version ' . nl2br( $t_version_info['description'] );
		?>
	</td>
	<?php
		$t_warning = '';
		$t_error = '';
		switch( $f_db_type ) {
			case 'mysql':
			case 'mysqli':
				if( version_compare( $t_version_info['version'], DB_MIN_VERSION_MYSQL, '<' ) ) {
					$t_error = 'MySQL ' . DB_MIN_VERSION_MYSQL . ' or later is required for installation.';
				}
				break;
			case 'mssql':
			case 'mssqlnative':
				if( version_compare( $t_version_info['version'], DB_MIN_VERSION_MSSQL, '<' ) ) {
					$t_error = 'SQL Server 2005 (' . DB_MIN_VERSION_MSSQL . ') or later is required for installation.';
				}
				break;
			case 'pgsql':
			case 'db2':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -458,7 +458,7 @@
 	<td bgcolor="#ffffff">
 		Checking Database Server Version
 		<?php
-		echo '<br /> Running ' . $f_db_type . ' version ' . nl2br( $t_version_info['description'] );
+		echo '<br /> Running ' . string_attribute( $f_db_type ) . ' version ' . nl2br( $t_version_info['description'] );
 		?>
 	</td>
 	<?php
@@ -581,7 +581,7 @@
 		Hostname (for Database Server)
 	</td>
 	<td>
-		<input name="hostname" type="textbox" value="<?php echo $f_hostname?>">
+		<input name="hostname" type="textbox" value="<?php echo string_attribute( $f_hostname ) ?>">
 	</td>
 </tr>
 
@@ -591,7 +591,7 @@
 		Username (for Database)
 	</td>
 	<td>
-		<input name="db_username" type="textbox" value="<?php echo $f_db_username?>">
+		<input name="db_username" type="textbox" value="<?php echo string_attribute( $f_db_username ) ?>">
 	</td>
 </tr>
 
@@ -614,7 +614,7 @@
 		Database name (for Database)
 	</td>
 	<td>
-		<input name="database_name" type="textbox" value="<?php echo $f_database_name?>">
+		<input name="database_name" type="textbox" value="<?php echo string_attribute( $f_database_name ) ?>">
 	</td>
 </tr>
 <?php
@@ -627,7 +627,7 @@
 		Admin Username (to <?php echo( !$g_database_upgrade ) ? 'create Database' : 'update Database'?> if required)
 	</td>
 	<td>
-		<input name="admin_username" type="textbox" value="<?php echo $f_admin_username?>">
+		<input name="admin_username" type="textbox" value="<?php echo string_attribute( $f_admin_username ) ?>">
 	</td>
 </tr>
 
@@ -639,7 +639,7 @@
 		<input name="admin_password" type="password" value="<?php
 			echo !is_blank( $f_admin_password ) && $f_admin_password == $f_db_password
 				? CONFIGURED_PASSWORD
-				: $f_admin_password;
+				: string_attribute( $f_admin_password );
 		?>">
 	</td>
 </tr>
@@ -1024,13 +1024,13 @@
 	# @todo to be written
 	# must post data gathered to preserve it
 	?>
-		<input name="hostname" type="hidden" value="<?php echo $f_hostname?>">
-		<input name="db_type" type="hidden" value="<?php echo $f_db_type?>">
-		<input name="database_name" type="hidden" value="<?php echo $f_database_name?>">
-		<input name="db_username" type="hidden" value="<?php echo $f_db_username?>">
-		<input name="db_password" type="hidden" value="<?php echo $f_db_password?>">
-		<input name="admin_username" type="hidden" value="<?php echo $f_admin_username?>">
-		<input name="admin_password" type="hidden" value="<?php echo $f_admin_password?>">
+		<input name="hostname" type="hidden" value="<?php echo string_attribute( $f_hostname ) ?>">
+		<input name="db_type" type="hidden" value="<?php echo string_attribute( $f_db_type ) ?>">
+		<input name="database_name" type="hidden" value="<?php echo string_attribute( $f_database_name ) ?>">
+		<input name="db_username" type="hidden" value="<?php echo string_attribute( $f_db_username ) ?>">
+		<input name="db_password" type="hidden" value="<?php echo string_attribute( f_db_password ) ?>">
+		<input name="admin_username" type="hidden" value="<?php echo string_attribute( $f_admin_username ) ?>">
+		<input name="admin_password" type="hidden" value="<?php echo string_attribute( $f_admin_password ) ?>">
 		<input name="log_queries" type="hidden" value="<?php echo( $f_log_queries ? 1 : 0 )?>">
 		<input name="db_exists" type="hidden" value="<?php echo( $f_db_exists ? 1 : 0 )?>">
 <?php
@@ -1330,20 +1330,20 @@
 	<td bgcolor="#ffffff">
 <form method='POST'>
 		<input name="install" type="hidden" value="<?php echo $t_install_state?>">
-		<input name="hostname" type="hidden" value="<?php echo $f_hostname?>">
-		<input name="db_type" type="hidden" value="<?php echo $f_db_type?>">
-		<input name="database_name" type="hidden" value="<?php echo $f_database_name?>">
-		<input name="db_username" type="hidden" value="<?php echo $f_db_username?>">
+		<input name="hostname" type="hidden" value="<?php echo string_attribute( $f_hostname ) ?>">
+		<input name="db_type" type="hidden" value="<?php echo string_attribute( $f_db_type ) ?>">
+		<input name="database_name" type="hidden" value="<?php echo string_attribute( $f_database_name ) ?>">
+		<input name="db_username" type="hidden" value="<?php echo string_attribute( $f_db_username ) ?>">
 		<input name="db_password" type="hidden" value="<?php
 			echo !is_blank( $f_db_password ) && $t_config_exists
 				? CONFIGURED_PASSWORD
-				: $f_db_password;
+				: string_attribute( $f_db_password );
 		?>">
 		<input name="admin_username" type="hidden" value="<?php echo $f_admin_username?>">
 		<input name="admin_password" type="hidden" value="<?php
 			echo !is_blank( $f_admin_password ) && $f_admin_password == $f_db_password
 				? CONFIGURED_PASSWORD
-				: $f_admin_password;
+				: string_attribute( $f_admin_password );
 		?>">
 		<input name="log_queries" type="hidden" value="<?php echo( $f_log_queries ? 1 : 0 )?>">
 		<input name="db_exists" type="hidden" value="<?php echo( $f_db_exists ? 1 : 0 )?>">
```
