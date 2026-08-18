# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 1049_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1049_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 4344-4384 of the vulnerable file.

 */
$g_global_settings = array(
	'global_settings', 'admin_checks', 'allow_signup', 'allow_anonymous_login',
	'anonymous_account', 'compress_html', 'allow_permanent_cookie',
	'cookie_time_length', 'cookie_path', 'cookie_domain',
	'cookie_prefix', 'string_cookie', 'project_cookie', 'view_all_cookie',
	'manage_config_cookie', 'logout_cookie',
	'bug_list_cookie', 'crypto_master_salt', 'custom_headers',
	'database_name', 'db_username', 'db_password', 'db_type',
	'db_table_prefix','db_table_suffix', 'display_errors', 'form_security_validation',
	'hostname','html_valid_tags', 'html_valid_tags_single_line', 'default_language',
	'language_auto_map', 'fallback_language', 'login_method', 'plugins_enabled',
	'session_save_path', 'session_validation', 'show_detailed_errors', 'show_queries_count',
	'show_timer', 'show_memory_usage', 'stop_on_errors', 'version_suffix', 'debug_email',
	'fileinfo_magic_db_file', 'css_include_file', 'css_rtl_include_file',
	'file_type_icons', 'path', 'short_path', 'absolute_path', 'core_path',
	'class_path','library_path', 'language_path', 'absolute_path_default_upload_folder',
	'ldap_simulation_file_path', 'plugin_path', 'bottom_include_page', 'top_include_page',
	'default_home_page', 'logout_redirect_page', 'manual_url', 'logo_url', 'wiki_engine_url',
	'cdn_enabled', 'public_config_names', 'email_login_enabled', 'email_ensure_unique',
	'impersonate_user_threshold', 'email_retry_in_days'
);

/**
 * List of config options available via SOAP API.
 * The following list of configuration options is used to check if it is
 * allowed to query a specific configuration option via SOAP API.
 * @global array $g_public_config_names
 */
$g_public_config_names = array(
	'access_levels_enum_string',
	'action_button_position',
	'add_bugnote_threshold',
	'add_profile_threshold',
	'admin_site_threshold',
	'allow_account_delete',
	'allow_anonymous_login',
	'allow_blank_email',
	'allow_delete_own_attachments',
	'allow_download_own_attachments',
	'allow_file_upload',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4361,7 +4361,7 @@
 	'ldap_simulation_file_path', 'plugin_path', 'bottom_include_page', 'top_include_page',
 	'default_home_page', 'logout_redirect_page', 'manual_url', 'logo_url', 'wiki_engine_url',
 	'cdn_enabled', 'public_config_names', 'email_login_enabled', 'email_ensure_unique',
-	'impersonate_user_threshold', 'email_retry_in_days'
+	'impersonate_user_threshold', 'email_retry_in_days', 'neato_tool', 'dot_tool'
 );
 
 /**
```
