# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3748_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3748_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 30-60 of the vulnerable file.

			if('ldap_agent_password' == $param) {
				OCP\Config::setAppValue('user_ldap', $param, base64_encode($_POST[$param]));
			} else {
				OCP\Config::setAppValue('user_ldap', $param, $_POST[$param]);
			}
		}
		elseif('ldap_tls' == $param) {
			// unchecked checkboxes are not included in the post paramters
				OCP\Config::setAppValue('user_ldap', $param, 0);
		}
		elseif('ldap_nocase' == $param) {
			OCP\Config::setAppValue('user_ldap', $param, 0);
		}

	}
}

// fill template
$tmpl = new OCP\Template( 'user_ldap', 'settings');
foreach($params as $param){
		$value = OCP\Config::getAppValue('user_ldap', $param,'');
		$tmpl->assign($param, $value);
}

// settings with default values
$tmpl->assign( 'ldap_port', OCP\Config::getAppValue('user_ldap', 'ldap_port', '389'));
$tmpl->assign( 'ldap_display_name', OCP\Config::getAppValue('user_ldap', 'ldap_display_name', 'uid'));
$tmpl->assign( 'ldap_group_member_assoc_attribute', OCP\Config::getAppValue('user_ldap', 'ldap_group_member_assoc_attribute', 'uniqueMember'));
$tmpl->assign( 'ldap_agent_password', base64_decode(OCP\Config::getAppValue('user_ldap', 'ldap_agent_password')));

return $tmpl->fetchPage();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,7 +47,7 @@
 // fill template
 $tmpl = new OCP\Template( 'user_ldap', 'settings');
 foreach($params as $param){
-		$value = OCP\Config::getAppValue('user_ldap', $param,'');
+		$value = htmlentities(OCP\Config::getAppValue('user_ldap', $param,''));
 		$tmpl->assign($param, $value);
 }
 
```
