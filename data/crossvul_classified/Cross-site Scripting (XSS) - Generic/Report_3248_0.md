# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3248_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3248_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 398-438 of the vulnerable file.

/**
 * Render navbar at the top of the page
 * @return null
 */
function layout_navbar() {
	$t_logo_url = config_get('logo_url');

	echo '<div id="navbar" class="navbar navbar-default navbar-collapse navbar-fixed-top noprint">';
	echo '<div id="navbar-container" class="navbar-container">';

	echo '<button id="menu-toggler" type="button" class="navbar-toggle menu-toggler pull-left hidden-lg" data-target="#sidebar">';
	echo '<span class="sr-only">Toggle sidebar</span>';
	echo '<span class="icon-bar"></span>';
	echo '<span class="icon-bar"></span>';
	echo '<span class="icon-bar"></span>';
	echo '</button>';

	echo '<div class="navbar-header">';
	echo '<a href="' . $t_logo_url . '" class="navbar-brand">';
	echo '<span class="smaller-75"> ';
	echo config_get('window_title');
	echo ' </span>';
	echo '</a>';

	$t_toggle_class = (OFF == config_get('show_avatar') ? 'navbar-toggle' : 'navbar-toggle-img');
	echo '<button type="button" class="navbar-toggle ' . $t_toggle_class . ' collapsed pull-right hidden-sm hidden-md hidden-lg" data-toggle="collapse" data-target=".navbar-buttons,.navbar-menu">';
	echo '<span class="sr-only">Toggle user menu</span>';
	if (auth_is_user_authenticated()) {
		layout_navbar_user_avatar();
	}
	echo '</button>';

	echo '</div>';

	echo '<div class="navbar-buttons navbar-header navbar-collapse collapse">';
	echo '<ul class="nav ace-nav">';
	if (auth_is_user_authenticated()) {
		# shortcuts button bar
		layout_navbar_button_bar();
		# projects dropdown menu
		layout_navbar_projects_menu();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -415,7 +415,7 @@
 	echo '<div class="navbar-header">';
 	echo '<a href="' . $t_logo_url . '" class="navbar-brand">';
 	echo '<span class="smaller-75"> ';
-	echo config_get('window_title');
+	echo string_display_line( config_get('window_title') );
 	echo ' </span>';
 	echo '</a>';
 
```
