# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 88_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `88_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 15-36 of the vulnerable file.

	$tpl->SetVariable("LINK", ilUtil::secureUrl(ILIAS_HTTP_PATH . '/ilias.php?baseClass=ilRepositoryGUI&amp;client_id=' . CLIENT_ID));
	$tpl->ParseCurrentBlock();

	$tpl->setCurrentBlock("content");
	$tpl->setVariable("ERROR_MESSAGE", ($_SESSION["failure"]));
	$tpl->setVariable("MESSAGE_HEADING", $lng->txt('error_sry_error'));

	//$tpl->parseCurrentBlock();

	ilSession::clear("referer");
	ilSession::clear("message");
	$tpl->show();
}
catch(Exception $e)
{
	if(defined('DEVMODE') && DEVMODE)
	{
		throw $e;
	}

	die($e->getMessage());
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,5 +32,7 @@
 		throw $e;
 	}
 
-	die($e->getMessage());
+	if (!($e instanceof \PDOException)) {
+		die($e->getMessage());
+	}
 }
```
