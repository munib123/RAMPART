# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3202_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3202_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php

class Users_View extends View
{
	public function __construct($page)
	{
		parent::__construct($page);
	}

	public function ShowList($columns, $data)
	{
		$title = 'Użytkownicy serwisu';
		$image = 'img/32x32/users_group.png';

		$attribs = array(
			array('width' => '5%',  'align' => 'center', 'visible' => '1'),
			array('width' => '8%', 'align' => 'left',   'visible' => '1', 'image' => '1'),
			array('width' => '5%',  'align' => 'left',   'visible' => '0'),
			array('width' => '8%', 'align' => 'left',   'visible' => '1'),
			array('width' => '10%', 'align' => 'left',   'visible' => '1'),
			array('width' => '10%', 'align' => 'left', 'visible' => '1'),
			array('width' => '5%',  'align' => 'center', 'visible' => '1'),
			array('width' => '10%', 'align' => 'center', 'visible' => '1'),
			array('width' => '5%', 'align' => 'center', 'visible' => '1'),
			array('width' => '5%', 'align' => 'center', 'visible' => '1'),
			array('width' => '5%', 'align' => 'center', 'visible' => '1'),
			array('width' => '5%',  'align' => 'center', 'visible' => '0'),
			array('width' => '15%', 'align' => 'center', 'visible' => '1'),
		);
		
		$actions = array(
			array('action' => 'view',    'icon' => 'info.png',   'title' => 'Podgląd'),
			array('action' => 'edit',    'icon' => 'edit.png',   'title' => 'Edytuj'),
			array('action' => 'setpass', 'icon' => 'access.png', 'title' => 'Hasło'),
			array('action' => 'delete',  'icon' => 'trash.png',  'title' => 'Usuń'),
		);
	
		$group_names = array('Guest', 'Adm', 'Opr', 'Usr');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,16 +14,16 @@
 
 		$attribs = array(
 			array('width' => '5%',  'align' => 'center', 'visible' => '1'),
-			array('width' => '8%', 'align' => 'left',   'visible' => '1', 'image' => '1'),
-			array('width' => '5%',  'align' => 'left',   'visible' => '0'),
-			array('width' => '8%', 'align' => 'left',   'visible' => '1'),
+			array('width' => '10%', 'align' => 'left',   'visible' => '1', 'image' => '1'),
+			array('width' => '10%',  'align' => 'left',   'visible' => '0'),
 			array('width' => '10%', 'align' => 'left',   'visible' => '1'),
-			array('width' => '10%', 'align' => 'left', 'visible' => '1'),
-			array('width' => '5%',  'align' => 'center', 'visible' => '1'),
+			array('width' => '10%', 'align' => 'left',   'visible' => '1'),
+			array('width' => '25%', 'align' => 'left', 'visible' => '1'),
+			array('width' => '5%',  'align' => 'left', 'visible' => '1'),
 			array('width' => '10%', 'align' => 'center', 'visible' => '1'),
 			array('width' => '5%', 'align' => 'center', 'visible' => '1'),
-			array('width' => '5%', 'align' => 'center', 'visible' => '1'),
-			array('width' => '5%', 'align' => 'center', 'visible' => '1'),
+			array('width' => '5%', 'align' => 'center', 'visible' => '0'),
+			array('width' => '5%', 'align' => 'center', 'visible' => '0'),
 			array('width' => '5%',  'align' => 'center', 'visible' => '0'),
 			array('width' => '15%', 'align' => 'center', 'visible' => '1'),
 		);
```
