# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3703_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3703_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 360-401 of the vulnerable file.

		{
			// Device has not been registered yet. Register it!
			
			// TODO: Formalize the user creation process. For now we are creating
			//		 a new user for every new device but eventually, we need
			//		 to be able to have multiple devices for each user
			
			// Name of the user
			$user_name = ($firstname AND $lastname)
			    ? $firstname.' '.$lastname
			    : '';
			
			// Email address
			$user_email = ($email) ? $email : $this->getRandomString();
			
			// Color
			$user_color = ($color) ? $color : $this->random_color();
			
			// Check if email exists
			
			$query = 'SELECT id FROM '.$this->table_prefix.'users WHERE `email` = \''.$user_email.'\' LIMIT 1;';
			$usercheck = $this->db->query($query);
			
			if ( isset($usercheck[0]->id) )
			{
				$user_id = $usercheck[0]->id;
			}
			else
			{
				// Create a new user
				$user = ORM::factory('user');
				$user->name = $user_name;
				$user->email = $user_email;
				$user->username = $this->getRandomString();
				$user->password = 'checkinuserpw';
				$user->color = $user_color;
				$user->add(ORM::factory('role', 'login'));
				$user_id = $user->save();

			}

			//	 TODO: When we have user registration down, we need to pass a user id here
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -377,8 +377,8 @@
 			
 			// Check if email exists
 			
-			$query = 'SELECT id FROM '.$this->table_prefix.'users WHERE `email` = \''.$user_email.'\' LIMIT 1;';
-			$usercheck = $this->db->query($query);
+			$query = 'SELECT id FROM `'.$this->table_prefix.'users` WHERE `email` = ? LIMIT 1;';
+			$usercheck = $this->db->query($query, $user_email);
 			
 			if ( isset($usercheck[0]->id) )
 			{
```
