# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3408_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3408_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 278-318 of the vulnerable file.

	}
}

/**
 * Get all the client information knowing only the id
 * Used on the Manage files page.
 *
 * @return array
 */
function get_client_by_id($client)
{
	global $dbh;
	$statement = $dbh->prepare("SELECT * FROM " . TABLE_USERS . " WHERE id=:id");
	$statement->bindParam(':id', $client, PDO::PARAM_INT);
	$statement->execute();
	$statement->setFetchMode(PDO::FETCH_ASSOC);

	while ( $row = $statement->fetch() ) {
		$information = array(
							'id'				=> $row['id'],
							'name'				=> $row['name'],
							'username'			=> $row['user'],
							'address'			=> $row['address'],
							'phone'				=> $row['phone'],
							'email'				=> $row['email'],
							'notify'			=> $row['notify'],
							'level'				=> $row['level'],
							'active'			=> $row['active'],
							'max_file_size'		=> $row['max_file_size'],
							'contact'			=> $row['contact'],
							'created_date'		=> $row['timestamp'],
							'created_by'		=> $row['created_by']
						);
		if ( !empty( $information ) ) {
			return $information;
		}
		else {
			return false;
		}
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -295,7 +295,7 @@
 	while ( $row = $statement->fetch() ) {
 		$information = array(
 							'id'				=> $row['id'],
-							'name'				=> $row['name'],
+							'name'				=> html_output($row['name']),
 							'username'			=> $row['user'],
 							'address'			=> $row['address'],
 							'phone'				=> $row['phone'],
@@ -334,7 +334,7 @@
 	while ( $row = $statement->fetch() ) {
 		$information = array(
 							'id'				=> $row['id'],
-							'name'				=> $row['name'],
+							'name'				=> html_output($row['name']),
 							'username'			=> $row['user'],
 							'address'			=> $row['address'],
 							'phone'				=> $row['phone'],
@@ -431,7 +431,7 @@
 			$information = array(
 								'id'				=> $row['id'],
 								'username'			=> $row['user'],
-								'name'				=> $row['name'],
+								'name'				=> html_output($row['name']),
 								'email'				=> $row['email'],
 								'level'				=> $row['level'],
 								'active'			=> $row['active'],
@@ -465,7 +465,7 @@
 		$information = array(
 							'id'				=> $row['id'],
 							'username'			=> $row['user'],
-							'name'				=> $row['name'],
+							'name'				=> html_output($row['name']),
 							'email'				=> $row['email'],
 							'level'				=> $row['level'],
 							'max_file_size'		=> $row['max_file_size'],
@@ -932,7 +932,7 @@
 
 	$layout = '<div class="row">
 					<div class="col-xs-12 branding_unlogged">
-						<img src="' . $branding_image . '" alt="' . THIS_INSTALL_SET_TITLE . '" />
+						<img src="' . $branding_image . '" alt="' . html_output(THIS_INSTALL_SET_TITLE) . '" />
 					</div>
 				</div>';
 
@@ -1103,11 +1103,11 @@
 	$action = $params['action'];
 	$timestamp = $params['timestamp'];
 	$owner_id = $params['owner_id'];
-	$owner_user = $params['owner_user'];
+	$owner_user = html_output($params['owner_user']);
 	$affected_file = $params['affected_file'];
 	$affected_file_name = $params['affected_file_name'];
 	$affected_account = $params['affected_account'];
-	$affected_account_name = $params['affected_account_name'];
+	$affected_account_name = html_output($params['affected_account_name']);
 	
 	switch ($action) {
 		case 0:
```
