# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5072_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5072_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 422-462 of the vulnerable file.

		}
		
	}
	if ($type===""){
		return;
	}
	
	//テンプレートフォルダの設定
    $tmplfld=assist_templatePath('headercode',"",$pi_name);
	if (file_exists ($tmplfld."/".$type.".thtml")) {

		$tpl = new Template($tmplfld);

		$tpl->set_file (array (
			'tpl' => $type.'.thtml',
			));
	
		$tpl->set_var('xhtml', XHTML);
		$tpl->set_var('site_url', $_CONF['site_url']);
		
		$tpl->set_var ('currenturl', $currenturl);
		
		$tpl->set_var ('site_name', $_CONF['site_name']);
		$tpl->set_var ('site_mail', $_CONF['site_mail']);
		
		$tpl->set_var ('og_title', $og_title);
		$tpl->set_var ('og_image', $og_image);
		$tpl->set_var ('og_description', $og_description);
		$tpl->set_var ('og_type', $og_type);
		
		
		//facebook
		$facebook_consumer_key = trim($_CONF['facebook_consumer_key']);
		$tpl->set_var ('facebook_consumer_key', $facebook_consumer_key);
		//$tpl->set_var ('fb_user_ids', $fb_user_ids);

		$tpl->parse ('output', 'tpl');
		$retval .= $tpl->finish ($tpl->get_var ('output'));
	}

	return $retval;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -439,7 +439,7 @@
 		$tpl->set_var('xhtml', XHTML);
 		$tpl->set_var('site_url', $_CONF['site_url']);
 		
-		$tpl->set_var ('currenturl', $currenturl);
+		$tpl->set_var ('currenturl', htmlspecialchars($currenturl, ENT_QUOTES, 'UTF-8'));
 		
 		$tpl->set_var ('site_name', $_CONF['site_name']);
 		$tpl->set_var ('site_mail', $_CONF['site_mail']);
```
