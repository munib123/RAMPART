# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3101_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3101_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 7575-7615 of the vulnerable file.

		upg_task_end();
	}

	if( upg_task_start( 11805, 'Upgrading collection-group permissions table...' ) )
	{	// part of 6.7.7-stable
		$DB->query( 'ALTER TABLE T_coll_group_perms
			ADD bloggroup_perm_analytics tinyint NOT NULL default 0' );
		$DB->query( 'UPDATE T_coll_group_perms
			  SET bloggroup_perm_analytics = 1
			WHERE bloggroup_perm_properties = 1' );
		upg_task_end();
	}

	if( upg_task_start( 11810, 'Upgrading plugins table...' ) )
	{	// part of 6.7.7-stable
		$DB->query( 'ALTER TABLE T_plugins
			MODIFY plug_priority TINYINT UNSIGNED NOT NULL default 50' );
		upg_task_end();
	}

	/*
	 * ADD UPGRADES __ABOVE__ IN A NEW UPGRADE BLOCK.
	 *
	 * YOU MUST USE:
	 * task_begin( 'Descriptive text about action...' );
	 * task_end();
	 *
	 * ALL DB CHANGES MUST BE EXPLICITLY CARRIED OUT. DO NOT RELY ON SCHEMA UPDATES!
	 * Schema updates do not survive after several incremental changes.
	 *
	 * NOTE: every change that gets done here, should bump {@link $new_db_version} (by 100).
	 */

	// Execute general upgrade tasks.
	// These tasks needs to be called after every upgrade process, except if they were already executed but the upgrade was not finished because of the max execution time check.
	if( param( 'exec_general_tasks', 'boolean', 1 ) )
	{	// We haven't executed these general tasks yet:

		// Update modules own b2evo tables
		echo get_install_format_text( "Calling modules for individual upgrades...<br>\n", 'br' );
		evo_flush();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7592,6 +7592,14 @@
 		upg_task_end();
 	}
 
+	if( upg_task_start( 11815, 'Updating file types table...' ) )
+	{ // part of 6.7.10-stable
+		$DB->query( 'UPDATE T_filetypes
+				SET ftyp_allowed = "admin"
+			WHERE ftyp_extensions REGEXP "[[:<:]]swf[[:>:]]"' );
+		upg_task_end();
+	}
+
 	/*
 	 * ADD UPGRADES __ABOVE__ IN A NEW UPGRADE BLOCK.
 	 *
```
