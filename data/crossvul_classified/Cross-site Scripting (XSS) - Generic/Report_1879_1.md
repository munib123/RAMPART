# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1879_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1879_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 521-561 of the vulnerable file.

	 */
	public function printAdminScripts() {
		wp_enqueue_script ( 'jquery' );
	}

	/**
	 * Extend admin header
	 *
	 * @see \WP_Piwik\Admin::extendAdminHeader()
	 */
	public function extendAdminHeader() {
		echo '<script type="text/javascript">var $j = jQuery.noConflict();</script>';
		echo '<script type="text/javascript">/* <![CDATA[ */(function() {var s = document.createElement(\'script\');var t = document.getElementsByTagName(\'script\')[0];s.type = \'text/javascript\';s.async = true;s.src = \'//api.flattr.com/js/0.6/load.js?mode=auto\';t.parentNode.insertBefore(s, t);})();/* ]]> */</script>';
	}

	/**
	 * Show credits
	 */
	public function showCredits() {
		?>
		<p><strong><?php _e('Thank you very much for your donation', 'wp-piwik'); ?>:</strong> Marco L., Rolf W., Tobias U., Lars K., Donna F., Kevin D., Ramos S., Thomas M., John C., Andreas G., Ben M., Myra R. I., Carlos U. R.-S., Oleg I., M. N., Daniel K., James L., Jochen K., Cyril P., Thomas K., Patrik K., <?php _e('the Piwik team itself','wp-piwik');?><?php _e(', and all people flattering this','wp-piwik'); ?>!</p>
		<p><?php _e('Graphs powered by <a href="http://www.jqplot.com/">jqPlot</a> (License: GPL 2.0 and MIT) and <a href="http://omnipotent.net/jquery.sparkline/">jQuery Sparklines</a> (License: New BSD License).','wp-piwik'); ?></p>
		<p><?php _e('Metabox support inspired by', 'wp-piwik'); echo ' <a href="http://www.code-styling.de/english/how-to-use-wordpress-metaboxes-at-own-plugins">Heiko Rabe\'s metabox demo plugin</a>.';?></p>
		<p><?php _e('Tabbed settings page suggested by the', 'wp-piwik'); echo' <a href="http://wp.smashingmagazine.com/2011/10/20/create-tabs-wordpress-settings-pages/">Smashing Magazine</a>.';?></p>
		<p><?php _e('Thank you very much','wp-piwik'); ?>, Besnik Bleta, FatCow, Rene, Fab, EzBizNiz, Gormer, Natalya, AggelioPolis, Web Hosting Geeks, Web Hosting Rating, Nata Strazda (Web Hosting Hub), Hossein (LibreOffice localization team), Ste &amp; Chris <?php _e('for your translation work','wp-piwik'); ?>!</p>
		<p><?php _e('Thank you very much, all users who send me mails containing criticism, commendation, feature requests and bug reports! You help me to make WP-Piwik much better.','wp-piwik'); ?></p>
		<p><?php _e('Thank <strong>you</strong> for using my plugin. It is the best commendation if my piece of code is really used!','wp-piwik'); ?></p>
		<?php
	}

	/**
	 * Show support information
	 */
	public function showSupport() {
		?><ul>
			<li><?php _e('The best place to get help:', 'wp-piwik'); ?> <a href="https://wordpress.org/support/plugin/wp-piwik"><?php _e('WP-Piwik support forum','wp-piwik'); ?></a></li>
			<li><?php _e('Please don\'t forget to vote the compatibility at the','wp-piwik'); ?> <a href="http://wordpress.org/extend/plugins/wp-piwik/">WordPress.org Plugin Directory</a>.</li>
		</ul>
		<h3><?php _e('Debugging', 'wp-piwik'); ?></h3>
		<p><?php _e('Either allow_url_fopen has to be enabled <em>or</em> cURL has to be available:', 'wp-piwik'); ?></p>
		<ol>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -538,11 +538,9 @@
 	 */
 	public function showCredits() {
 		?>
-		<p><strong><?php _e('Thank you very much for your donation', 'wp-piwik'); ?>:</strong> Marco L., Rolf W., Tobias U., Lars K., Donna F., Kevin D., Ramos S., Thomas M., John C., Andreas G., Ben M., Myra R. I., Carlos U. R.-S., Oleg I., M. N., Daniel K., James L., Jochen K., Cyril P., Thomas K., Patrik K., <?php _e('the Piwik team itself','wp-piwik');?><?php _e(', and all people flattering this','wp-piwik'); ?>!</p>
+		<p><strong><?php _e('Thank you very much for your donation', 'wp-piwik'); ?>:</strong> Marco L., Rolf W., Tobias U., Lars K., Donna F., Kevin D., Ramos S., Thomas M., John C., Andreas G., Ben M., Myra R. I., Carlos U. R.-S., Oleg I., M. N., Daniel K., James L., Jochen K., Cyril P., Thomas K., Patrik K., Zach, Sebastian W., Peakkom, Patrik K., <?php _e('the Piwik team itself','wp-piwik');?><?php _e(', and all people flattering this','wp-piwik'); ?>!</p>
 		<p><?php _e('Graphs powered by <a href="http://www.jqplot.com/">jqPlot</a> (License: GPL 2.0 and MIT) and <a href="http://omnipotent.net/jquery.sparkline/">jQuery Sparklines</a> (License: New BSD License).','wp-piwik'); ?></p>
-		<p><?php _e('Metabox support inspired by', 'wp-piwik'); echo ' <a href="http://www.code-styling.de/english/how-to-use-wordpress-metaboxes-at-own-plugins">Heiko Rabe\'s metabox demo plugin</a>.';?></p>
-		<p><?php _e('Tabbed settings page suggested by the', 'wp-piwik'); echo' <a href="http://wp.smashingmagazine.com/2011/10/20/create-tabs-wordpress-settings-pages/">Smashing Magazine</a>.';?></p>
-		<p><?php _e('Thank you very much','wp-piwik'); ?>, Besnik Bleta, FatCow, Rene, Fab, EzBizNiz, Gormer, Natalya, AggelioPolis, Web Hosting Geeks, Web Hosting Rating, Nata Strazda (Web Hosting Hub), Hossein (LibreOffice localization team), Ste &amp; Chris <?php _e('for your translation work','wp-piwik'); ?>!</p>
+		<p><?php _e('Thank you very much','wp-piwik'); ?> <a href="https://www.transifex.com/projects/p/wp-piwik/">Transifex Translation Community</a> <?php _e('for your translation work','wp-piwik'); ?>!</p>
 		<p><?php _e('Thank you very much, all users who send me mails containing criticism, commendation, feature requests and bug reports! You help me to make WP-Piwik much better.','wp-piwik'); ?></p>
 		<p><?php _e('Thank <strong>you</strong> for using my plugin. It is the best commendation if my piece of code is really used!','wp-piwik'); ?></p>
 		<?php
```
