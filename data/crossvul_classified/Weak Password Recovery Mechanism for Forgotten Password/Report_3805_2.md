# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 3805_2
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3805_2`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 343-364 of the vulnerable file.

	}
	
	/**
	 * Get user's dashboard
	 */
	public function dashboard()
	{
		if ($this->has_permission('admin_ui'))
			return 'admin';
		
		if ($this->has_permission('member_ui'))
			return 'members';
		
		// Just in case someone has a login only role
		if ($this->has(ORM::factory('role','login')))
			return '';
		
		// Send anyone else to login
		return 'login';
	}

} // End User_Model
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -360,5 +360,40 @@
 		// Send anyone else to login
 		return 'login';
 	}
+	
+	/**
+	 * Get a new forgotten password challenge token for this user
+	 * @param string $salt Optional salt for token generation (use this)
+	 * @return string
+	 */
+	public function forgot_password_token()
+	{
+		return $this->_forgot_password_token();
+	}
+
+	/**
+	 * Check to see if forgotten password token is valid
+	 * @param string $token token to check
+	 * @return boolean is token valid
+	 **/
+	public function check_forgot_password_token($token)
+	{
+		$salt = substr($token, 0, 32);
+		return $this->_forgot_password_token($salt) == $token;
+	}
+
+	/**
+	 * Generate a forgotten password challenge token for this user
+	 * @param string $salt Optional salt for token generation (only use this for checking a token in URL)
+	 * @return string token
+	 */
+	private function _forgot_password_token($salt = FALSE)
+	{
+		// Secret consists of email and the last_login field.
+		// So as soon as the user logs in again, the reset link expires automatically.
+		$salt = $salt ? $salt : text::random('alnum', 32); // Limited charset to keep it URL friendly
+		$key = Kohana::config('settings.forgot_password_secret');
+		return $salt . hash_hmac('sha1', $this->last_login . $this->email, $salt . $key);
+	}
 
 } // End User_Model
```
