# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2378_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2378_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 678-718 of the vulnerable file.

		{
			// TODO lan
			$mes->addError("You don't have enough permissions to do this.", 'default', true);
			// TODO lan
			$lan = 'Security violation (not enough permissions) - Administrator --ADMIN_UID-- (--ADMIN_NAME--, --ADMIN_EMAIL--) tried to make --UID-- (--NAME--, --EMAIL--) system admin';
			$search = array('--UID--', '--NAME--', '--EMAIL--', '--ADMIN_UID--', '--ADMIN_NAME--', '--ADMIN_EMAIL--');
			$replace = array($sysuser->getId(), $sysuser->getName(), $sysuser->getValue('email'), $user->getId(), $user->getName(), $user->getValue('email'));
			
			e107::getLog()->add('USET_08', str_replace($search, $replace, $lan), E_LOG_INFORMATIVE);
			
			$this->redirect('list', 'main', true);
		}
		
		if(!$sysuser->getId())
		{
			// TODO lan
			$mes->addError("User not found.", 'default', true);
			$this->redirect('list', 'main', true);
		}
		
		if(!$sysuser->isAdmin())
		{
			$sysuser->set('user_admin', 1)->save(); //"user","user_admin='1' WHERE user_id={$userid}"
			$lan = str_replace(array('--UID--', '--NAME--', '--EMAIL--'), array($sysuser->getId(), $sysuser->getName(), $sysuser->getValue('email')), USRLAN_164);
			e107::getLog()->add('USET_08', $lan, E_LOG_INFORMATIVE);
			$mes->addSuccess($lan);
		}
		
		if($this->getPosted('update_admin')) e107::getUserPerms()->updatePerms($userid, $_POST['perms']);
	}
	
	/**
	 * Admin manage page
	 */
	public function AdminPage()
	{
		$request = $this->getRequest();
		$response = $this->getResponse();
		$sysuser = e107::getSystemUser($request->getId(), false);
		//$sysuser->load($request->getId(), true);
		$prm = e107::getUserPerms();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -695,15 +695,23 @@
 			$this->redirect('list', 'main', true);
 		}
 		
-		if(!$sysuser->isAdmin())
-		{
-			$sysuser->set('user_admin', 1)->save(); //"user","user_admin='1' WHERE user_id={$userid}"
-			$lan = str_replace(array('--UID--', '--NAME--', '--EMAIL--'), array($sysuser->getId(), $sysuser->getName(), $sysuser->getValue('email')), USRLAN_164);
-			e107::getLog()->add('USET_08', $lan, E_LOG_INFORMATIVE);
-			$mes->addSuccess($lan);
-		}
-		
-		if($this->getPosted('update_admin')) e107::getUserPerms()->updatePerms($userid, $_POST['perms']);
+	
+		if($this->getPosted('update_admin'))
+		{
+			 e107::getUserPerms()->updatePerms($userid, $_POST['perms']);
+			 $this->redirect('list', 'main', true);
+		}
+		
+		if(!$sysuser->isAdmin()) // Security Check Only. Admin status check is added during 'updatePerms'. 
+		{
+		//	$sysuser->set('user_admin', 1)->save(); //"user","user_admin='1' WHERE user_id={$userid}"
+		//	$lan = str_replace(array('--UID--', '--NAME--', '--EMAIL--'), array($sysuser->getId(), $sysuser->getName(), $sysuser->getValue('email')), USRLAN_164);
+		//	e107::getLog()->add('USET_08', $lan, E_LOG_INFORMATIVE);
+		//	$mes->addSuccess($lan);
+			$mes->addWarning("You are about to make User #<b>".$sysuser->getId()."</b> : <b>".$sysuser->getName()."</b> (".$sysuser->getValue('email').") an <b>administrator</b>."); ///TODO LAN
+			$mes->addWarning("Set the permissions and click <b>Update</b> to proceed or <b>Back</b> to abort.");
+		}
+		
 	}
 	
 	/**
```
