# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3742_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3742_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 101-124 of the vulnerable file.

			}
			OC_Util::redirectToDefaultPage();
		} else {
			$error = true;
		}
	
	// The user is already authenticated using Apaches AuthType Basic... very usable in combination with LDAP
	} elseif(isset($_SERVER["PHP_AUTH_USER"]) && isset($_SERVER["PHP_AUTH_PW"])){
		if (OC_User::login($_SERVER["PHP_AUTH_USER"],$_SERVER["PHP_AUTH_PW"]))	{
			//OC_Log::write('core',"Logged in with HTTP Authentication",OC_Log::DEBUG);
			OC_User::unsetMagicInCookie();
			$_REQUEST['redirect_url'] = (isset($_SERVER['REQUEST_URI'])?$_SERVER['REQUEST_URI']:'');
			OC_Util::redirectToDefaultPage();
		}else{
			$error = true;
		}
	}
	if(!array_key_exists('sectoken', $_SESSION) || (array_key_exists('sectoken', $_SESSION) && is_null(OC::$REQUESTEDFILE)) || substr(OC::$REQUESTEDFILE, -3) == 'php'){
		$sectoken=rand(1000000,9999999);
		$_SESSION['sectoken']=$sectoken;
		$redirect_url = (isset($_REQUEST['redirect_url'])) ? $_REQUEST['redirect_url'] : $_SERVER['REQUEST_URI'];
		OC_Template::printGuestPage('', 'login', array('error' => $error, 'sectoken' => $sectoken, 'redirect' => $redirect_url));
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,7 +118,7 @@
 	if(!array_key_exists('sectoken', $_SESSION) || (array_key_exists('sectoken', $_SESSION) && is_null(OC::$REQUESTEDFILE)) || substr(OC::$REQUESTEDFILE, -3) == 'php'){
 		$sectoken=rand(1000000,9999999);
 		$_SESSION['sectoken']=$sectoken;
-		$redirect_url = (isset($_REQUEST['redirect_url'])) ? $_REQUEST['redirect_url'] : $_SERVER['REQUEST_URI'];
+		$redirect_url = (isset($_REQUEST['redirect_url'])) ? strip_tags($_REQUEST['redirect_url']) : $_SERVER['REQUEST_URI'];
 		OC_Template::printGuestPage('', 'login', array('error' => $error, 'sectoken' => $sectoken, 'redirect' => $redirect_url));
 	}
 }
```
