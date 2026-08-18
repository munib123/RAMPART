# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3202_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3202_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-40 of the vulnerable file.

<?php

class Roles_View extends View
{
	public function __construct($page)
	{
		parent::__construct($page);
	}

	public function ShowList($columns, $data)
	{
		$title = 'Role użytkowników';
		$image = 'img/32x32/lock_go.png';

		$attribs = array(
			array('width' => '5%',  'align' => 'center', 'visible' => '1'),
			array('width' => '10%', 'align' => 'center', 'visible' => '1', 'image' => '1'),
			array('width' => '15%', 'align' => 'center', 'visible' => '1'),
			array('width' => '10%', 'align' => 'center', 'visible' => '1'),
			array('width' => '50%', 'align' => 'center', 'visible' => '1'),
			array('width' => '10%', 'align' => 'center', 'visible' => '1'),
		);
		
		$actions = array(
			array('action' => 'view',   'icon' => 'info.png',  'title' => 'Podgląd'),
			array('action' => 'edit',   'icon' => 'edit.png',  'title' => 'Edytuj'),
			array('action' => 'delete', 'icon' => 'trash.png', 'title' => 'Usuń'),
		);
	
		foreach ($data as $k => $v)
		{
			foreach ($v as $key => $value)
			{
				if ($key == 'user_login')
				{
					if ($value == $_SESSION['user_login'])
					{
						$data[$k]['user_login'] = '<b style="color: blue;">' . $data[$k]['user_login'] . '</b>';
					}
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,11 +13,11 @@
 		$image = 'img/32x32/lock_go.png';
 
 		$attribs = array(
-			array('width' => '5%',  'align' => 'center', 'visible' => '1'),
-			array('width' => '10%', 'align' => 'center', 'visible' => '1', 'image' => '1'),
-			array('width' => '15%', 'align' => 'center', 'visible' => '1'),
-			array('width' => '10%', 'align' => 'center', 'visible' => '1'),
-			array('width' => '50%', 'align' => 'center', 'visible' => '1'),
+			array('width' => '10%',  'align' => 'center', 'visible' => '1'),
+			array('width' => '15%', 'align' => 'left', 'visible' => '1', 'image' => '1'),
+			array('width' => '20%', 'align' => 'left', 'visible' => '1'),
+			array('width' => '10%', 'align' => 'left', 'visible' => '1'),
+			array('width' => '30%', 'align' => 'left', 'visible' => '1'),
 			array('width' => '10%', 'align' => 'center', 'visible' => '1'),
 		);
 		
```
