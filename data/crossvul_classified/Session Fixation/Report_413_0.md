# CrossVul Fix Pair: Session Fixation in php
**Pair ID:** 413_0
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `413_0`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```php
Lines 101-141 of the vulnerable file.

				$chain_entry = sqlfetch(sqlquery("SELECT * FROM bigtree_user_sessions WHERE email = '$user' AND chain = '".sqlescape($chain)."'"));

				if ($chain_entry && $chain_entry["csrf_token"]) {
					// If both chain and session are legit, log them in
					if ($chain_entry["id"] == $session) {
						$f = sqlfetch(sqlquery("SELECT * FROM bigtree_users WHERE email = '$user'"));
						if ($f) {
							// Generate a random CSRF token
							$csrf_token = base64_encode(openssl_random_pseudo_bytes(32));
							$csrf_token_field = "__csrf_token_".BigTree::randomString(32)."__";

							// Setup session
							$this->ID = $f["id"];
							$this->User = $user;
							$this->Level = $f["level"];
							$this->Name = $f["name"];
							$this->Permissions = json_decode($f["permissions"],true);
							$this->CSRFToken = $csrf_token;
							$this->CSRFTokenField = $csrf_token_field;

							$_SESSION["bigtree_admin"]["id"] = $f["id"];
							$_SESSION["bigtree_admin"]["email"] = $f["email"];
							$_SESSION["bigtree_admin"]["name"] = $f["name"];
							$_SESSION["bigtree_admin"]["level"] = $f["level"];
							$_SESSION["bigtree_admin"]["csrf_token"] = $csrf_token;
							$_SESSION["bigtree_admin"]["csrf_token_field"] = $csrf_token_field;

							// Delete existing session
							sqlquery("DELETE FROM bigtree_user_sessions WHERE id = '".sqlescape($session)."'");

							// Generate a random session id
							$session = uniqid("session-",true);
							while (sqlrows(sqlquery("SELECT id FROM bigtree_user_sessions WHERE id = '".sqlescape($session)."'"))) {
								$session = uniqid("session-",true);
							}

							// Create a new session with the same chain
							sqlquery("INSERT INTO bigtree_user_sessions (`id`,`chain`,`email`,`csrf_token`,`csrf_token_field`) VALUES ('".sqlescape($session)."','".sqlescape($chain)."','$user','$csrf_token','$csrf_token_field')");
							setcookie('bigtree_admin[login]',json_encode(array($session,$chain)),strtotime("+1 month"),str_replace(DOMAIN,"",WWW_ROOT),"",false,true);
						}
					// Chain is legit and session isn't -- someone has taken your cookies
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,6 +118,7 @@
 							$this->CSRFToken = $csrf_token;
 							$this->CSRFTokenField = $csrf_token_field;
 
+							session_regenerate_id();
 							$_SESSION["bigtree_admin"]["id"] = $f["id"];
 							$_SESSION["bigtree_admin"]["email"] = $f["email"];
 							$_SESSION["bigtree_admin"]["name"] = $f["name"];
@@ -6053,6 +6054,7 @@
 						setcookie('bigtree_admin[login]', $cookie_value, strtotime("+1 month"), $cookie_domain, "", false, true);
 					}
 
+					session_regenerate_id();
 					$_SESSION["bigtree_admin"]["id"] = $user["id"];
 					$_SESSION["bigtree_admin"]["email"] = $user["email"];
 					$_SESSION["bigtree_admin"]["level"] = $user["level"];
@@ -6184,6 +6186,7 @@
 						setcookie('bigtree_admin[login]', $cookie_value, strtotime("+1 month"), $cookie_domain, "", false, true);
 					}
 
+					session_regenerate_id();
 					$_SESSION["bigtree_admin"]["id"] = $user["id"];
 					$_SESSION["bigtree_admin"]["email"] = $user["email"];
 					$_SESSION["bigtree_admin"]["level"] = $user["level"];
```
