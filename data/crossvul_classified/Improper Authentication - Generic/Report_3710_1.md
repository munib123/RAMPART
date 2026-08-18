# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 3710_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3710_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 185-226 of the vulnerable file.

	 */
	public function get_response()
	{
		return $this->response;
	}

	/**
	 * Gets the name of the task being handled by the API service
	 *
	 * @return string
	 */
	public function get_task_name()
	{
		return $this->task_name;
	}

	/**
	 * Log user in.
	 * This method is mainly used for admin tasks performed via the API
	 *
	 * @param string $username User's username.
	 * @param string $password User's password.
	 * @return mixed user_id, FALSE if authentication fails
	 */
	public function _login($admin = FALSE)
    {
		$auth = Auth::instance();

		// Is user previously authenticated?
		if ($auth->logged_in())
		{
			// Check if admin privileges are required
			if ($admin == FALSE OR $auth->has_permission('admin_ui'))
			{
				return $auth->get_user()->id;
			}
			else
			{
				return FALSE;
			}
		}
		else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,11 +202,11 @@
 	 * Log user in.
 	 * This method is mainly used for admin tasks performed via the API
 	 *
-	 * @param string $username User's username.
-	 * @param string $password User's password.
+	 * @param bool $admin require admin access?
+	 * @param bool $member require member access?
 	 * @return mixed user_id, FALSE if authentication fails
 	 */
-	public function _login($admin = FALSE)
+	public function _login($admin = FALSE, $member = FALSE)
     {
 		$auth = Auth::instance();
 
@@ -215,6 +215,11 @@
 		{
 			// Check if admin privileges are required
 			if ($admin == FALSE OR $auth->has_permission('admin_ui'))
+			{
+				return $auth->get_user()->id;
+			}
+			// Check if member perms required, assume admins also have member perms
+			else if ($member == FALSE OR $auth->has_permission('member_ui') OR $auth->has_permission('admin_ui'))
 			{
 				return $auth->get_user()->id;
 			}
```
