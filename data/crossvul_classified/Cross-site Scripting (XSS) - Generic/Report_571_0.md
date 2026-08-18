# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 571_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `571_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
/**
 * Plugin Name: Simple Download Monitor
 * Plugin URI: https://www.tipsandtricks-hq.com/simple-wordpress-download-monitor-plugin
 * Description: Easily manage downloadable files and monitor downloads of your digital files from your WordPress site.
 * Version: 3.5.3
 * Author: Tips and Tricks HQ, Ruhul Amin, Josh Lobe
 * Author URI: https://www.tipsandtricks-hq.com/development-center
 * License: GPL2
 * Text Domain: simple-download-monitor
 * Domain Path: /languages/
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WP_SIMPLE_DL_MONITOR_VERSION', '3.5.3');
define('WP_SIMPLE_DL_MONITOR_DIR_NAME', dirname(plugin_basename(__FILE__)));
define('WP_SIMPLE_DL_MONITOR_URL', plugins_url('', __FILE__));
define('WP_SIMPLE_DL_MONITOR_PATH', plugin_dir_path(__FILE__));
define('WP_SIMPLE_DL_MONITOR_SITE_HOME_URL', home_url());
define('WP_SDM_LOG_FILE', WP_SIMPLE_DL_MONITOR_PATH . 'sdm-debug-log.txt');

global $sdm_db_version;
$sdm_db_version = '1.2';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
  * Plugin Name: Simple Download Monitor
  * Plugin URI: https://www.tipsandtricks-hq.com/simple-wordpress-download-monitor-plugin
  * Description: Easily manage downloadable files and monitor downloads of your digital files from your WordPress site.
- * Version: 3.5.3
+ * Version: 3.5.4
  * Author: Tips and Tricks HQ, Ruhul Amin, Josh Lobe
  * Author URI: https://www.tipsandtricks-hq.com/development-center
  * License: GPL2
@@ -15,7 +15,7 @@
     exit;
 }
 
-define('WP_SIMPLE_DL_MONITOR_VERSION', '3.5.3');
+define('WP_SIMPLE_DL_MONITOR_VERSION', '3.5.4');
 define('WP_SIMPLE_DL_MONITOR_DIR_NAME', dirname(plugin_basename(__FILE__)));
 define('WP_SIMPLE_DL_MONITOR_URL', plugins_url('', __FILE__));
 define('WP_SIMPLE_DL_MONITOR_PATH', plugin_dir_path(__FILE__));
@@ -313,7 +313,7 @@
 	echo '<br /><br />';
 
 	echo '<div class="sdm-download-edit-file-url-section">';
-	echo '<input id="sdm_upload" type="text" size="100" name="sdm_upload" value="' . $old_value . '" placeholder="http://..." />';
+	echo '<input id="sdm_upload" type="text" size="100" name="sdm_upload" value="' . esc_url($old_value) . '" placeholder="http://..." />';
 	echo '</div>';
 
 	echo '<br />';
@@ -356,7 +356,7 @@
 	_e('Manually enter a valid URL, or click "Select Image" to upload (or choose) the file thumbnail image.', 'simple-download-monitor');
 	?>
 	<br /><br />
-	<input id="sdm_upload_thumbnail" type="text" size="100" name="sdm_upload_thumbnail" value="<?php echo $old_value; ?>" placeholder="http://..." />
+	<input id="sdm_upload_thumbnail" type="text" size="100" name="sdm_upload_thumbnail" value="<?php echo esc_url($old_value); ?>" placeholder="http://..." />
 	<br /><br />
 	<input id="upload_thumbnail_button" type="button" class="button-primary" value="<?php _e('Select Image', 'simple-download-monitor'); ?>" />
 	<input id="remove_thumbnail_button" type="button" class="button" value="<?php _e('Remove Image', 'simple-download-monitor'); ?>" />
@@ -401,7 +401,7 @@
 	echo '<div class="sdm-download-edit-offset-count">';
 	_e('Offset Count: ', 'simple-download-monitor');
 	echo '<br />';
-	echo ' <input type="text" size="10" name="sdm_count_offset" value="' . $value . '" />';
+	echo ' <input type="text" size="10" name="sdm_count_offset" value="' . esc_attr($value) . '" />';
 	echo '<p class="description">' . __('Enter any positive or negative numerical value; to offset the download count shown to the visitors (when using the download counter shortcode).', 'simple-download-monitor') . '</p>';
 	echo '</div>';
 
@@ -425,14 +425,14 @@
 	echo '<div class="sdm-download-edit-filesize">';
 	_e('File Size: ', 'simple-download-monitor');
 	echo '<br />';
-	echo ' <input type="text" name="sdm_item_file_size" value="' . $file_size . '" size="20" />';
+	echo ' <input type="text" name="sdm_item_file_size" value="' . esc_attr($file_size) . '" size="20" />';
 	echo '<p class="description">' . __('Enter the size of this file (example value: 2.15 MB). You can show this value in the fancy display by using a shortcode parameter.', 'simple-download-monitor') . '</p>';
 	echo '</div>';
 
 	echo '<div class="sdm-download-edit-version">';
 	_e('Version: ', 'simple-download-monitor');
 	echo '<br />';
-	echo ' <input type="text" name="sdm_item_version" value="' . $version . '" size="20" />';
+	echo ' <input type="text" name="sdm_item_version" value="' . esc_attr($version) . '" size="20" />';
 	echo '<p class="description">' . __('Enter the version number for this item if any (example value: v2.5.10). You can show this value in the fancy display by using a shortcode parameter.', 'simple-download-monitor') . '</p>';
 	echo '</div>';
 
@@ -473,7 +473,7 @@
 	    return;
 
 	if (isset($_POST['sdm_upload'])) {
-	    update_post_meta($post_id, 'sdm_upload', $_POST['sdm_upload']);
+	    update_post_meta($post_id, 'sdm_upload', sanitize_text_field($_POST['sdm_upload']));
 	}
     }
 
@@ -496,7 +496,7 @@
 	    return;
 
 	if (isset($_POST['sdm_upload_thumbnail'])) {
-	    update_post_meta($post_id, 'sdm_upload_thumbnail', $_POST['sdm_upload_thumbnail']);
+	    update_post_meta($post_id, 'sdm_upload_thumbnail', sanitize_text_field($_POST['sdm_upload_thumbnail']));
 	}
     }
 
@@ -528,11 +528,11 @@
 	}
 
 	if (isset($_POST['sdm_item_file_size'])) {
-	    update_post_meta($post_id, 'sdm_item_file_size', $_POST['sdm_item_file_size']);
+	    update_post_meta($post_id, 'sdm_item_file_size', sanitize_text_field($_POST['sdm_item_file_size']));
 	}
 
 	if (isset($_POST['sdm_item_version'])) {
-	    update_post_meta($post_id, 'sdm_item_version', $_POST['sdm_item_version']);
+	    update_post_meta($post_id, 'sdm_item_version', sanitize_text_field($_POST['sdm_item_version']));
 	}
     }
 
```
