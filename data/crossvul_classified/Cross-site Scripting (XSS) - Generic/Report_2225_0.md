# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2225_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2225_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 17-57 of the vulnerable file.

if(!getperms('0'))
{
	header('location:'.e_BASE.'index.php');
	exit();
}

if(isset($_POST['back']))
{
	header("location: ".e_SELF);
	exit();
}

include_lan(e_LANGUAGEDIR.e_LANGUAGE.'/admin/lan_'.e_PAGE);		



$e_sub_cat = 'database';

$frm = e107::getForm();
$mes = e107::getMessage();

/*
 * Execute trigger
 */
if(isset($_POST['db_execute']))
{
	$type = key($_POST['db_execute']);
	
	if(!varset($_POST['db_execute']))
	{
		$mes->add(DBLAN_53, E_MESSAGE_WARNING);
	}
	else
	{
		$_POST[$type] = true;
	}
}




```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,16 @@
 
 $frm = e107::getForm();
 $mes = e107::getMessage();
+
+if(isset($_GET['mode']))
+{
+    $_GET['mode'] = preg_match('/[^\w-]/', '', $_GET['mode']);
+}
+
+if(isset($_GET['type']))
+{
+    $_GET['type'] = preg_replace('/[^\w-]/', '', $_GET['type']);
+}
 
 /*
  * Execute trigger
```
