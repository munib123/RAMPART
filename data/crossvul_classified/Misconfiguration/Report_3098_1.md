# CrossVul Fix Pair: Initialization of a Resource with an Insecure Default in php
**Pair ID:** 3098_1
**Vulnerability Class:** Misconfiguration
**CWE:** CWE-1188
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3098_1`)

## Vulnerability Information & PoC

## Description
Initialization of a Resource with an Insecure Default - Developers often choose default values that leave the product as open and easy to use as possible out-of-the-box, under the assumption that the administrator can (or should) change the default value.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php
/**
 * Gets the email message from the user's mailbox to add as
 * a WordPress post. Mailbox connection information must be
 * configured under Settings > Writing
 *
 * @package WordPress
 */

/** Make sure that the WordPress bootstrap has run before continuing. */
require(dirname(__FILE__) . '/wp-load.php');

/** This filter is documented in wp-admin/options.php */
if ( ! apply_filters( 'enable_post_by_email_configuration', true ) )
	wp_die( __( 'This action has been disabled by the administrator.' ), 403 );

/**
 * Fires to allow a plugin to do a complete takeover of Post by Email.
 *
 * @since 2.9.0
 */
do_action( 'wp-mail.php' );

/** Get the POP3 class with which to access the mailbox. */
require_once( ABSPATH . WPINC . '/class-pop3.php' );

/** Only check at this interval for new messages. */
if ( !defined('WP_MAIL_INTERVAL') )
	define('WP_MAIL_INTERVAL', 300); // 5 minutes

$last_checked = get_transient('mailserver_last_checked');

if ( $last_checked )
	wp_die(__('Slow down cowboy, no need to check for new mails so often!'));

set_transient('mailserver_last_checked', true, WP_MAIL_INTERVAL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,12 @@
 /** This filter is documented in wp-admin/options.php */
 if ( ! apply_filters( 'enable_post_by_email_configuration', true ) )
 	wp_die( __( 'This action has been disabled by the administrator.' ), 403 );
+
+$mailserver_url = get_option( 'mailserver_url' );
+
+if ( 'mail.example.com' === $mailserver_url || empty( $mailserver_url ) ) {
+	wp_die( __( 'This action has been disabled by the administrator.' ), 403 );
+}
 
 /**
  * Fires to allow a plugin to do a complete takeover of Post by Email.
```
