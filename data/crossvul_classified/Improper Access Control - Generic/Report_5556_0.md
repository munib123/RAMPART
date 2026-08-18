# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 5556_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5556_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 999-1039 of the vulnerable file.

	return $return;
}

////////////////////////////////////////////////////////////////////////////////
///
/// \fn checkForGroupName($name, $type, $id, $extraid)
///
/// \param $name - the name of a group
/// \param $type - user or resource
/// \param $id - id of a group to ignore
/// \param $extraid - if $type is resource, this is a resource type id; if
///                   $type is user, this is an affiliation id
///
/// \return 1 if $name is already in the associated table, 0 if not
///
/// \brief checks for $name being in usergroup/resource group (based on $type)
/// except for $id
///
////////////////////////////////////////////////////////////////////////////////
function checkForGroupName($name, $type, $id, $extraid) {
	if($type == "user")
		$query = "SELECT id FROM usergroup "
		       . "WHERE name = '$name' AND "
		       .       "affiliationid = $extraid";
	else
		$query = "SELECT id FROM resourcegroup "
		       . "WHERE name = '$name' AND "
		       .       "resourcetypeid = $extraid";
	if(! empty($id))
		$query .= " AND id != $id";
	$qh = doQuery($query, 101);
	if(mysql_num_rows($qh))
		return 1;
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
///
/// \fn updateGroup($data)
///
/// \param $data - an array returned from processGroupInput
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1016,6 +1016,7 @@
 ///
 ////////////////////////////////////////////////////////////////////////////////
 function checkForGroupName($name, $type, $id, $extraid) {
+	$name = mysql_real_escape_string($name);
 	if($type == "user")
 		$query = "SELECT id FROM usergroup "
 		       . "WHERE name = '$name' AND "
@@ -1090,9 +1091,9 @@
 ///
 ////////////////////////////////////////////////////////////////////////////////
 function addGroup($data) {
-	if($data['editgroupid'] == 0 || $data['editgroupid'] == '')
-		$data['editgroupid'] = 'NULL';
 	if($data['type'] == "user") {
+		if($data['editgroupid'] == 0 || $data['editgroupid'] == '')
+			$data['editgroupid'] = 'NULL';
 		if(! array_key_exists('custom', $data))
 			$data['custom'] = 1;
 		elseif($data['custom'] == 0) {
```
