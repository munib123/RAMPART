# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 398_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `398_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 37-77 of the vulnerable file.

	$navibars->add_tab_content_row(
		array(
			'<label>'.t(378, 'License').'</label>',
			'<a href="http://www.gnu.org/licenses/gpl-2.0.html" target="_blank">GPL v2</a>'
		)
	);
											
	$navibars->add_tab_content_row(
		array(
			'<label>'.t(219, 'Copyright').'</label>',
			'<a href="http://www.naviwebs.com" target="_blank">&copy; 2010 - '.date('Y').', Naviwebs.com</a>'
		)
	);


	$navibars->add_tab(t(218, 'Third party libraries'));	
	
	$navibars->add_tab_content_row(
		array(
			'<label>'.t(218, 'Third party libraries').'</label>',
			'<a href="http://www.tinymce.com" target="_blank">TinyMCE 4.8.0c</a><br />'
		)
	);

	// note: the tinymce-codemirror plugin has Apache 2 License, but the author Arjan (from Webgear.nl) has given permission to use and include the code in this application
    $navibars->add_tab_content_row(
    	array(
    		'<label>&nbsp;</label>',
			'<a href="https://github.com/christiaan/tinymce-codemirror" target="_blank">TinyMCE CodeMirror plugin v1.4+ (commit #1d31634)</a><br />'
		)
	);

	$navibars->add_tab_content_row(
		array(
			'<label>&nbsp;</label>',
			'<a href="https://github.com/Matmusia/magicline" target="_blank">TinyMCE magic line plugin v1.2.3_nv</a><br />'
		)
	);

	$navibars->add_tab_content_row(
		array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,7 +54,7 @@
 	$navibars->add_tab_content_row(
 		array(
 			'<label>'.t(218, 'Third party libraries').'</label>',
-			'<a href="http://www.tinymce.com" target="_blank">TinyMCE 4.8.0c</a><br />'
+			'<a href="http://www.tinymce.com" target="_blank">TinyMCE 4.8.3</a><br />'
 		)
 	);
 
```
