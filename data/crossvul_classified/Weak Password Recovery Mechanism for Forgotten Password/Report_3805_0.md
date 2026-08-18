# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 3805_0
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3805_0`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 303-349 of the vulnerable file.

				// Existing User??
				if ($user->loaded)
				{

					// Determine which reset method to use. The options are to use the RiverID server
					//  or to use the normal method which just resets the password locally.
					if (Kohana::config('riverid.enable') == TRUE AND ! empty($user->riverid))
					{
						// Reset on RiverID Server

						$secret_link = url::site('login/index/'.$user->id.'/%token%?reset');
						$message = $this->_email_resetlink_message($user->name, $secret_link);

						$riverid = new RiverID;
						$riverid->email = $post->resetemail;
						$riverid->requestpassword($message);
					}
					else
					{
						// Reset locally

						// Secret consists of email and the last_login field.
						// So as soon as the user logs in again,
						// the reset link expires automatically.
						$secret = $auth->hash_password($user->email.$user->last_login);
						$secret_link = url::site('login/index/'.$user->id.'/'.$secret.'?reset');
						$email_sent = $this->_email_resetlink($post->resetemail,$user->name,$secret_link);
					}

					if ($email_sent == TRUE)
					{
						$message_class = 'login_success';
						$message = Kohana::lang('ui_main.login_confirmation_sent');
					}
					else
					{
						$message_class = 'login_error';
						$message = Kohana::lang('ui_main.unable_send_email');
					}

					$success = TRUE;
					$action = "";
				}
			}
			else
			{
				// repopulate the form fields
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -320,13 +320,9 @@
 					else
 					{
 						// Reset locally
-
-						// Secret consists of email and the last_login field.
-						// So as soon as the user logs in again,
-						// the reset link expires automatically.
-						$secret = $auth->hash_password($user->email.$user->last_login);
-						$secret_link = url::site('login/index/'.$user->id.'/'.$secret.'?reset');
-						$email_sent = $this->_email_resetlink($post->resetemail,$user->name,$secret_link);
+						$secret = $user->forgot_password_token();
+						$secret_link = url::site('login/index/'.$user->id.'/'.urlencode($secret).'?reset');
+						$email_sent = $this->_email_resetlink($post->resetemail, $user->name, $secret_link);
 					}
 
 					if ($email_sent == TRUE)
@@ -870,8 +866,7 @@
 			else
 			{
 				// Use Standard
-
-				if($auth->hash_password($user->email.$user->last_login, $auth->find_salt($token)) == $token)
+				if($user->check_forgot_password_token($token))
 				{
 					$user->password = $password;
 					$user->save();
```
