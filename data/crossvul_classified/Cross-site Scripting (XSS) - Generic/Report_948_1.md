# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 948_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `948_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 181-221 of the vulnerable file.

				'welcome_page_display'	=> array('none')
			),

			'contacts' => array(
				'enable'			=> array(false, 'Enable contacts'),
				'allow_sync'		=> array(false),
				'sync_interval'		=> array(20),
				'type'				=> array('sqlite', ''),
				'pdo_dsn'			=> array('mysql:host=127.0.0.1;port=3306;dbname=rainloop', ''),
				'pdo_user'			=> array('root', ''),
				'pdo_password'		=> array('', ''),
				'suggestions_limit' => array(30)
			),

			'security' => array(
				'csrf_protection'	=> array(true,
					'Enable CSRF protection (http://en.wikipedia.org/wiki/Cross-site_request_forgery)'),

				'custom_server_signature'	=> array('RainLoop'),
				'x_frame_options_header'	=> array(''),

				'openpgp'					=> array(false),

				'admin_login'				=> array('admin', 'Login and password for web admin panel'),
				'admin_password'			=> array('12345'),
				'allow_admin_panel'			=> array(true, 'Access settings'),
				'allow_two_factor_auth'		=> array(false),
				'force_two_factor_auth'		=> array(false),
				'hide_x_mailer_header'		=> array(false),
				'admin_panel_host'			=> array(''),
				'admin_panel_key'			=> array('admin'),
				'content_security_policy'	=> array(''),
				'core_install_access_domain' => array('')
			),

			'ssl' => array(
				'verify_certificate'	=> array(false, 'Require verification of SSL certificate used.'),
				'allow_self_signed'		=> array(true, 'Allow self-signed certificates. Requires verify_certificate.'),
				'cafile'			=> array('', 'Location of Certificate Authority file on local filesystem (/etc/ssl/certs/ca-certificates.crt)'),
				'capath'			=> array('', 'capath must be a correctly hashed certificate directory. (/etc/ssl/certs/)'),
				'client_cert'			=> array('', 'Location of client certificate file (pem format with private key) on local filesystem'),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,7 +198,8 @@
 
 				'custom_server_signature'	=> array('RainLoop'),
 				'x_frame_options_header'	=> array(''),
-
+				'x_xss_protection_header'	=> array('1; mode=block'),
+				
 				'openpgp'					=> array(false),
 
 				'admin_login'				=> array('admin', 'Login and password for web admin panel'),
```
