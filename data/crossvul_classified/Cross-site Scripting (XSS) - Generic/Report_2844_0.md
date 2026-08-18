# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2844_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2844_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 67-107 of the vulnerable file.

	$refreshIsLogout = 'false';
	$myrefresh['seconds'] = $refresh['seconds'];
	$myrefresh['page']    = (strpos($refresh['page'], '?') ? '&':'?') . 'header=false';
} elseif (isset($refresh)) {
	$refreshIsLogout = 'false';
	$myrefresh['seconds'] = $refresh;
	$myrefresh['page']    = $_SERVER['REQUEST_URI'] . (strpos($_SERVER['REQUEST_URI'], '?') ? '&':'?') . 'header=false';;
} elseif (read_config_option('auth_cache_enabled') == 'on' && isset($_COOKIE['cacti_remembers'])) {
	$myrefresh['seconds'] = 99999999;
	$myrefresh['page']    = 'index.php';
	$refreshIsLogout = 'false';
} else {
	$myrefresh['seconds'] = ini_get('session.gc_maxlifetime');
	$myrefresh['page']    = $config['url_path'] . 'logout.php?action=timeout';
	$refreshIsLogout = 'true';
} ?>
<script type='text/javascript'>
	var cactiVersion='<?php print $config['cacti_version'];?>';
	var theme='<?php print get_selected_theme();?>';
	var refreshIsLogout=<?php print $refreshIsLogout;?>;
	var refreshPage='<?php print $myrefresh['page'];?>';
	var refreshMSeconds=<?php print $myrefresh['seconds']*1000;?>;
	var urlPath='<?php print $config['url_path'];?>';
	var previousPage='';
	var requestURI='<?php print $_SERVER['REQUEST_URI'];?>';
	var searchFilter='<?php print __('Enter a search term');?>';
	var searchRFilter='<?php print __('Enter a regular expression');?>';
	var noFileSelected='<?php print __('No file selected');?>';
	var timeGraphView='<?php print __('Time Graph View');?>';
	var filterSettingsSaved='<?php print __('Filter Settings Saved');?>';
	var spikeKillResuls='<?php print __('SpikeKill Results');?>';
	var utilityView='<?php print __('Utility View');?>';
	var realtimeClickOn='<?php print __('Click to view just this Graph in Realtime');?>';
	var realtimeClickOff='<?php print __('Click again to take this Graph out of Realtime');?>';
	var treeView='<?php print __('Tree View');?>';
	var listView='<?php print __('List View');?>';
	var previewView='<?php print __('Preview View');?>';
	var cactiHome='<?php print __('Cacti Home');?>';
	var cactiProjectPage='<?php print __('Cacti Project Page');?>';
	var cactiCommunityForum='<?php print __('Cacti Community Forum');?>';
	var reportABug='<?php print __('Report a bug');?>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,11 +84,11 @@
 	var cactiVersion='<?php print $config['cacti_version'];?>';
 	var theme='<?php print get_selected_theme();?>';
 	var refreshIsLogout=<?php print $refreshIsLogout;?>;
-	var refreshPage='<?php print $myrefresh['page'];?>';
+	var refreshPage='<?php print htmlspecialchars($myrefresh['page']);?>';
 	var refreshMSeconds=<?php print $myrefresh['seconds']*1000;?>;
 	var urlPath='<?php print $config['url_path'];?>';
 	var previousPage='';
-	var requestURI='<?php print $_SERVER['REQUEST_URI'];?>';
+	var requestURI='<?php print htmlspecialchars($_SERVER['REQUEST_URI']);?>';
 	var searchFilter='<?php print __('Enter a search term');?>';
 	var searchRFilter='<?php print __('Enter a regular expression');?>';
 	var noFileSelected='<?php print __('No file selected');?>';
```
