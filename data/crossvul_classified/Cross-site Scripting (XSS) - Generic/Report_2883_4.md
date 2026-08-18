# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2883_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2883_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 9-49 of the vulnerable file.

 *
 * @link              https://github.com/faiyazalam
 * @package           User_Login_History
 *
 * @wordpress-plugin
 * Plugin Name:       User Login History
 * Plugin URI:        https://github.com/faiyazalam
 * Description:       Easily tracks user login with a set of multiple attributes like ip, login/logout/last-seen time, country, username, user role, browser, OS etc.
 * Version:           1.6
 * Author:            Er Faiyaz Alam
 * Author URI:        https://github.com/faiyazalam
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       user-login-history
 * Domain Path:       /languages
 */
// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}
require_once plugin_dir_path(__FILE__) . 'includes/user-login-history-config.php';

/**
 * The code that runs during plugin activation.
 */
require_once plugin_dir_path(__FILE__) . 'includes/class-user-login-history-activator.php';

/**
 * The code that runs during plugin deactivation.
 */
require_once plugin_dir_path(__FILE__) . 'includes/class-user-login-history-deactivator.php';

/** This action is documented in includes/class-user-login-history-activator.php */
register_activation_hook(__FILE__, array('User_Login_History_Activator', 'activate'));

/** This action is documented in includes/class-user-login-history-deactivator.php */
register_deactivation_hook(__FILE__, array('User_Login_History_Deactivator', 'deactivate'));

/** The template tags accessible for public use */
//require_once plugin_dir_path( __FILE__ ) . 'public/user-login-history-functions.php';

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,9 @@
 if (!defined('WPINC')) {
     die;
 }
+
 require_once plugin_dir_path(__FILE__) . 'includes/user-login-history-config.php';
+require_once plugin_dir_path(__FILE__) . 'includes/class-user-login-history-error-handler.php';
 
 /**
  * The code that runs during plugin activation.
```
