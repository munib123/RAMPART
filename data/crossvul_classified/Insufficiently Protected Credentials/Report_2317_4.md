# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 2317_4
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2317_4`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 43-83 of the vulnerable file.

		add_menu_page(__('Database', 'wp-dbmanager'), __('Database', 'wp-dbmanager'), 'manage_database', 'wp-dbmanager/database-manager.php', '', 'dashicons-archive');
	}
	if (function_exists('add_submenu_page')) {
		add_submenu_page('wp-dbmanager/database-manager.php', __('Backup DB', 'wp-dbmanager'), __('Backup DB', 'wp-dbmanager'), 'manage_database', 'wp-dbmanager/database-backup.php');
		add_submenu_page('wp-dbmanager/database-manager.php', __('Manage Backup DB', 'wp-dbmanager'), __('Manage Backup DB', 'wp-dbmanager'), 'manage_database', 'wp-dbmanager/database-manage.php');
		add_submenu_page('wp-dbmanager/database-manager.php', __('Optimize DB', 'wp-dbmanager'), __('Optimize DB', 'wp-dbmanager'), 'manage_database', 'wp-dbmanager/database-optimize.php');
		add_submenu_page('wp-dbmanager/database-manager.php', __('Repair DB', 'wp-dbmanager'), __('Repair DB', 'wp-dbmanager'), 'manage_database', 'wp-dbmanager/database-repair.php');
		add_submenu_page('wp-dbmanager/database-manager.php', __('Empty/Drop Tables', 'wp-dbmanager'), __('Empty/Drop Tables', 'wp-dbmanager'), 'manage_database', 'wp-dbmanager/database-empty.php');
		add_submenu_page('wp-dbmanager/database-manager.php', __('Run SQL Query', 'wp-dbmanager'), __('Run SQL Query', 'wp-dbmanager'), 'manage_database', 'wp-dbmanager/database-run.php');
		add_submenu_page('wp-dbmanager/database-manager.php', __('DB Options', 'wp-dbmanager'),  __('DB Options', 'wp-dbmanager'), 'manage_database', 'wp-dbmanager/wp-dbmanager.php', 'dbmanager_options');
	}
}


### Funcion: Database Manager Cron
add_filter('cron_schedules', 'cron_dbmanager_reccurences');
add_action('dbmanager_cron_backup', 'cron_dbmanager_backup');
add_action('dbmanager_cron_optimize', 'cron_dbmanager_optimize');
add_action('dbmanager_cron_repair', 'cron_dbmanager_repair');
function cron_dbmanager_backup() {
	global $wpdb;
	$backup_options = get_option('dbmanager_options');
	$backup_email = stripslashes($backup_options['backup_email']);
	if(intval($backup_options['backup_period']) > 0) {
		$backup = array();
		$backup['date'] = current_time('timestamp');
		$backup['mysqldumppath'] = $backup_options['mysqldumppath'];
		$backup['mysqlpath'] = $backup_options['mysqlpath'];
		$backup['path'] = $backup_options['path'];
		$backup['password'] = str_replace('$', '\$', DB_PASSWORD);
		$backup['host'] = DB_HOST;
		$backup['port'] = '';
		$backup['sock'] = '';
		if(strpos(DB_HOST, ':') !== false) {
			$db_host = explode(':', DB_HOST);
			$backup['host'] = $db_host[0];
			if(intval($db_host[1]) != 0) {
				$backup['port'] = ' --port="'.intval($db_host[1]).'"';
			} else {
				$backup['sock'] = ' --socket="'.$db_host[1].'"';
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,7 +60,6 @@
 add_action('dbmanager_cron_optimize', 'cron_dbmanager_optimize');
 add_action('dbmanager_cron_repair', 'cron_dbmanager_repair');
 function cron_dbmanager_backup() {
-	global $wpdb;
 	$backup_options = get_option('dbmanager_options');
 	$backup_email = stripslashes($backup_options['backup_email']);
 	if(intval($backup_options['backup_period']) > 0) {
@@ -87,14 +86,14 @@
 		if(intval($backup_options['backup_gzip']) == 1) {
 			$backup['filename'] = $backup['date'].'_-_'.DB_NAME.'.sql.gz';
 			$backup['filepath'] = $backup['path'].'/'.$backup['filename'];
-			$backup['command'] = $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].' --add-drop-table --skip-lock-tables '.DB_NAME.' | gzip > '.$brace.$backup['filepath'].$brace;
+			$backup['command'] = escapeshellcmd( $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].' --add-drop-table --skip-lock-tables '.DB_NAME ). ' | gzip > '.escapeshellcmd( $brace.$backup['filepath'].$brace );
 		} else {
 			$backup['filename'] = $backup['date'].'_-_'.DB_NAME.'.sql';
 			$backup['filepath'] = $backup['path'].'/'.$backup['filename'];
-			$backup['command'] = $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].' --add-drop-table --skip-lock-tables '.DB_NAME.' > '.$brace.$backup['filepath'].$brace;
+			$backup['command'] = escapeshellcmd( $brace.$backup['mysqldumppath'].$brace.' --force --host="'.$backup['host'].'" --user="'.DB_USER.'" --password="'.$backup['password'].'"'.$backup['port'].$backup['sock'].' --add-drop-table --skip-lock-tables '.DB_NAME ). ' > '.escapeshellcmd( $brace.$backup['filepath'].$brace );
 		}
 		execute_backup($backup['command']);
-		if( !empty( $backup_email ) )
+		if( ! empty( $backup_email ) )
 		{
 			dbmanager_email_backup( $backup_email, $backup['filepath'] );
 		}
@@ -217,16 +216,16 @@
 		return sprintf( __( '%s is not a valid mysql path', 'wp-dbmanager' ), stripslashes( $backup_options['mysqlpath'] ) );
 	}
 
-	if(substr(PHP_OS, 0, 3) == 'WIN') {
+	if( substr( PHP_OS, 0, 3 ) === 'WIN' ) {
 		$writable_dir = $backup_options['path'];
 		$tmpnam = $writable_dir.'/wp-dbmanager.bat';
-		$fp = fopen($tmpnam, 'w');
-		fwrite($fp, $command);
-		fclose($fp);
-		system($tmpnam.' > NUL', $error);
-		unlink($tmpnam);
+		$fp = fopen( $tmpnam, 'w' );
+		fwrite ($fp, $command );
+		fclose( $fp );
+		system( $tmpnam.' > NUL', $error );
+		unlink( $tmpnam );
 	} else {
-		passthru($command, $error);
+		passthru( $command, $error );
 	}
 	return $error;
 }
```
