# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2452_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2452_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 140-180 of the vulnerable file.


include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}

$tab_array = array();
$tab_array[] = array(gettext("Users"), true, "system_usermanager.php");
$tab_array[] = array(gettext("Groups"), false, "system_groupmanager.php");
$tab_array[] = array(gettext("Settings"), false, "system_usermanager_settings.php");
$tab_array[] = array(gettext("Authentication Servers"), false, "system_authservers.php");
display_top_tabs($tab_array);

$form = new Form();

$section = new Form_Section('User Privileges');

$name_string = $a_user['name'];
if (!empty($a_user['descr'])) {
	$name_string .= " ({$a_user['descr']})";
}

$section->addInput(new Form_StaticText(
	'User',
	$name_string
));

$section->addInput(new Form_Select(
	'sysprivs',
	'*Assigned privileges',
	null,
	build_priv_list(),
	true
))->addClass('multiselect')
  ->setHelp('Hold down CTRL (PC)/COMMAND (Mac) key to select multiple items.');

$section->addInput(new Form_Select(
	'shadow',
	'Shadow',
	null,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -157,7 +157,7 @@
 
 $name_string = $a_user['name'];
 if (!empty($a_user['descr'])) {
-	$name_string .= " ({$a_user['descr']})";
+	$name_string .= " (" . htmlspecialchars($a_user['descr']) . ")";
 }
 
 $section->addInput(new Form_StaticText(
```
