# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 619_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `619_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 677-734 of the vulnerable file.

							'type' => 'string',
							'null' => false,
					),
					'block_old_event_alert' => array(
							'level' => 1,
							'description' => 'Enable this setting to start blocking alert e-mails for old events. The exact timing of what constitutes an old event is defined by MISP.block_old_event_alert_age.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => false,
					),
					'block_old_event_alert_age' => array(
							'level' => 1,
							'description' => 'If the MISP.block_old_event_alert setting is set, this setting will control how old an event can be for it to be alerted on. The "Date" field of the event is used. Expected format: integer, in days',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testForNumeric',
							'type' => 'numeric',
							'null' => false,
					),
					'rh_shell_fix' => array(
							'level' => 1,
							'description' => 'If you are running CentOS or RHEL using SCL and are having issues with the Background workers not responding to start/stop/restarts via the worker interface, enable this setting. This will pre-pend the shell execution commands with the default path to rh-php56 (/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin).',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true,
					),
					'rh_shell_fix_path' => array(
							'level' => 1,
							'description' => 'If you have rh_shell_fix enabled, the default PATH for rh-php56 is added (/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin). If you prefer to use a different path, you can set it here.',
							'value' => '/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin',
							'errorMessage' => '',
							'test' => 'testForPath',
							'type' => 'string',
							'null' => true,
					),
					'tmpdir' => array(
							'level' => 1,
							'description' => 'Please indicate the temp directory you wish to use for certain functionalities in MISP. By default this is set to /tmp and will be used among others to store certain temporary files extracted from imports during the import process.',
							'value' => '/tmp',
							'errorMessage' => '',
							'test' => 'testForPath',
							'type' => 'string',
							'null' => true,
					),
					'custom_css' => array(
							'level' => 2,
							'description' => 'If you would like to customise the css, simply drop a css file in the /var/www/MISP/webroot/css directory and enter the name here.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForStyleFile',
							'type' => 'string',
							'null' => true,
					),
					'proposals_block_attributes' => array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -694,24 +694,6 @@
 							'test' => 'testForNumeric',
 							'type' => 'numeric',
 							'null' => false,
-					),
-					'rh_shell_fix' => array(
-							'level' => 1,
-							'description' => 'If you are running CentOS or RHEL using SCL and are having issues with the Background workers not responding to start/stop/restarts via the worker interface, enable this setting. This will pre-pend the shell execution commands with the default path to rh-php56 (/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin).',
-							'value' => false,
-							'errorMessage' => '',
-							'test' => 'testBool',
-							'type' => 'boolean',
-							'null' => true,
-					),
-					'rh_shell_fix_path' => array(
-							'level' => 1,
-							'description' => 'If you have rh_shell_fix enabled, the default PATH for rh-php56 is added (/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin). If you prefer to use a different path, you can set it here.',
-							'value' => '/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin',
-							'errorMessage' => '',
-							'test' => 'testForPath',
-							'type' => 'string',
-							'null' => true,
 					),
 					'tmpdir' => array(
 							'level' => 1,
```
