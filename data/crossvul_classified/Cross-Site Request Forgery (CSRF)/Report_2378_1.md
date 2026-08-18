# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2378_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2378_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1581-1606 of the vulnerable file.

		$a_name = $row['user_name'];

		$perm = "";

		foreach($permArray as $value)
		{
			$value = $tp->toDB($value);
			if ($value == "0")
			{
				if (!getperms('0')) { $value = ""; break; }
				$perm = "0"; break;
			}

			if ($value)
			{
				$perm .= $value.".";
			}
	 	}
		
		//$sql->db_Update("user", "user_perms='{$perm}' WHERE user_id='{$modID}' ") 
		e107::getMessage()->addAuto($sysuser->set('user_perms', $perm)->save(), 'update', sprintf(LAN_UPDATED, $tp->toDB($_POST['ad_name'])), false, false);
		$logMsg = str_replace(array('--ID--', '--NAME--'),array($modID, $a_name),ADMSLAN_72).$perm;
		e107::getLog()->add('ADMIN_01',$logMsg,E_LOG_INFORMATIVE,'');
	}

}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1598,6 +1598,13 @@
 	 	}
 		
 		//$sql->db_Update("user", "user_perms='{$perm}' WHERE user_id='{$modID}' ") 
+		if(!$sysuser->isAdmin())
+		{
+			$sysuser->set('user_admin', 1)->save();
+			$lan = str_replace(array('--UID--', '--NAME--', '--EMAIL--'), array($sysuser->getId(), $sysuser->getName(), $sysuser->getValue('email')), USRLAN_164);
+			e107::getLog()->add('USET_08', $lan, E_LOG_INFORMATIVE);
+		}
+		
 		e107::getMessage()->addAuto($sysuser->set('user_perms', $perm)->save(), 'update', sprintf(LAN_UPDATED, $tp->toDB($_POST['ad_name'])), false, false);
 		$logMsg = str_replace(array('--ID--', '--NAME--'),array($modID, $a_name),ADMSLAN_72).$perm;
 		e107::getLog()->add('ADMIN_01',$logMsg,E_LOG_INFORMATIVE,'');
```
