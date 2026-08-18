# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4138_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4138_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 104-144 of the vulnerable file.

			if(!preg_match('/.+Page$/',$classPath)){
				$classPath .= '.IndexPage';
			}
		}

		//タブの設定
		if(preg_match('/^Inquiry/',$classPath)){
			CMSApplication::setActiveTab(1);
		}
		if(preg_match('/^Form/',$classPath)){
			CMSApplication::setActiveTab(2);
		}
		if(preg_match('/^Config/',$classPath)){
			CMSApplication::setActiveTab(3);
		}
		if(preg_match('/^Help/',$classPath)){
			CMSApplication::setActiveTab(4);
		}

		if(!SOY2HTMLFactory::pageExists($classPath)){
			return $classPath;
		}

		$webPage = &SOY2HTMLFactory::createInstance($classPath, array(
			"arguments" => $args
		));

		try{
			ob_start();
			$webPage->display();
			$html = ob_get_contents();
			ob_end_clean();
		}catch(Exception $e){

		}

		return $html;
	}

}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,7 +121,7 @@
 		}
 
 		if(!SOY2HTMLFactory::pageExists($classPath)){
-			return $classPath;
+			return "エラーが発生しました。";
 		}
 
 		$webPage = &SOY2HTMLFactory::createInstance($classPath, array(
```
