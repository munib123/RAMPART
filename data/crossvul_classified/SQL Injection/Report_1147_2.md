# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1147_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1147_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 27-67 of the vulnerable file.


//includes
	include "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";

//check permissions
	if (permission_exists('call_broadcast_edit')) {
		//access granted
	}
	else {
		echo "access denied";
		exit;
	}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//set the action with add or update
	if (isset($_REQUEST["id"])) {
		$action = "update";
		$call_broadcast_uuid = check_str($_REQUEST["id"]);
	}
	else {
		$action = "add";
	}

//function to Upload CSV/TXT file
	function upload_file($sql,$broadcast_phone_numbers) {
		$upload_csv = $sql = '';
		if (isset($_FILES['broadcast_phone_numbers_file']) && !empty($_FILES['broadcast_phone_numbers_file']) && $_FILES['broadcast_phone_numbers_file']['size'] > 0) {
			$filename=$_FILES["broadcast_phone_numbers_file"]["tmp_name"];
			$file_extension = array('application/octet-stream','application/vnd.ms-excel','text/plain','text/csv','text/tsv');
			if (in_array($_FILES['broadcast_phone_numbers_file']['type'],$file_extension)) {											
					$file = fopen($filename, "r");
					$count = 0;
					while (($getData = fgetcsv($file, 0, "\n")) !== FALSE)
					{
						$count++;
						if ($count == 1) { continue; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,16 +44,16 @@
 	$text = $language->get();
 
 //set the action with add or update
-	if (isset($_REQUEST["id"])) {
+	if (is_uuid($_REQUEST["id"])) {
 		$action = "update";
-		$call_broadcast_uuid = check_str($_REQUEST["id"]);
+		$call_broadcast_uuid = $_REQUEST["id"];
 	}
 	else {
 		$action = "add";
 	}
 
 //function to Upload CSV/TXT file
-	function upload_file($sql,$broadcast_phone_numbers) {
+	function upload_file($sql, $broadcast_phone_numbers) {
 		$upload_csv = $sql = '';
 		if (isset($_FILES['broadcast_phone_numbers_file']) && !empty($_FILES['broadcast_phone_numbers_file']) && $_FILES['broadcast_phone_numbers_file']['size'] > 0) {
 			$filename=$_FILES["broadcast_phone_numbers_file"]["tmp_name"];
@@ -94,33 +94,32 @@
 
 //get the http post variables and set them to php variables
 	if (count($_POST)>0) {
-		$broadcast_name = check_str($_POST["broadcast_name"]);
-		$broadcast_description = check_str($_POST["broadcast_description"]);
-		$broadcast_timeout = check_str($_POST["broadcast_timeout"]);
-		$broadcast_concurrent_limit = check_str($_POST["broadcast_concurrent_limit"]);
-		//$recording_uuid = check_str($_POST["recording_uuid"]);
-		$broadcast_caller_id_name = check_str($_POST["broadcast_caller_id_name"]);
-		$broadcast_caller_id_number = check_str($_POST["broadcast_caller_id_number"]);
-		$broadcast_destination_type = check_str($_POST["broadcast_destination_type"]);
-		$broadcast_phone_numbers = check_str($_POST["broadcast_phone_numbers"]);
-		$broadcast_avmd = check_str($_POST["broadcast_avmd"]);
-		$broadcast_destination_data = check_str($_POST["broadcast_destination_data"]);
+		$broadcast_name = $_POST["broadcast_name"];
+		$broadcast_description = $_POST["broadcast_description"];
+		$broadcast_timeout = $_POST["broadcast_timeout"];
+		$broadcast_concurrent_limit = $_POST["broadcast_concurrent_limit"];
+		//$recording_uuid = $_POST["recording_uuid"];
+		$broadcast_caller_id_name = $_POST["broadcast_caller_id_name"];
+		$broadcast_caller_id_number = $_POST["broadcast_caller_id_number"];
+		$broadcast_destination_type = $_POST["broadcast_destination_type"];
+		$broadcast_phone_numbers = $_POST["broadcast_phone_numbers"];
+		$broadcast_avmd = $_POST["broadcast_avmd"];
+		$broadcast_destination_data = $_POST["broadcast_destination_data"];
 
 		if (if_group("superadmin")){
-			$broadcast_accountcode = check_str($_POST["broadcast_accountcode"]);
-		}
-		elseif (if_group("admin") && file_exists($_SERVER["PROJECT_ROOT"]."/app/billing/app_config.php")){
-			$sql_accountcode = "SELECT COUNT(*) as count FROM v_billings WHERE domain_uuid = '".$_SESSION['domain_uuid']."' AND type_value='".$_POST["accountcode"]."'";
-			$prep_statement_accountcode = $db->prepare(check_sql($sql_accountcode));
-			$prep_statement_accountcode->execute();
-			$row_accountcode = $prep_statement_accountcode->fetch(PDO::FETCH_ASSOC);
-			if ($row_accountcode['count'] > 0) {
-				$broadcast_accountcode = check_str($_POST["broadcast_accountcode"]);
-			}
-			else {
-				$broadcast_accountcode = $_SESSION['domain_name'];
-			}
-			unset($sql_accountcode, $prep_statement_accountcode, $row_accountcode);
+			$broadcast_accountcode = $_POST["broadcast_accountcode"])
+		}
+		else if (if_group("admin") && file_exists($_SERVER["PROJECT_ROOT"]."/app/billing/app_config.php")){
+			$sql = "select count(*) ";
+			$sql .= "from v_billings ";
+			$sql .= "where domain_uuid = :domain_uuid ";
+			$sql .= "and type_value = :type_value ";
+			$parameters['domain_uuid'] = $_SESSION['domain_uuid'];
+			$parameters['type_value'] = $_POST['accountcode'];
+			$database = new database;
+			$num_rows = $database->select($sql, $parameters, 'column');
+			$broadcast_accountcode = $num_rows > 0 ? $_POST["broadcast_accountcode"] : $_SESSION['domain_name'];
+			unset($sql, $parameters, $num_rows);
 		}
 		else{
 			$broadcast_accountcode = $_SESSION['domain_name'];
@@ -131,7 +130,7 @@
 
 	$msg = '';
 	if ($action == "update") {
-		$call_broadcast_uuid = check_str($_POST["call_broadcast_uuid"]);
+		$call_broadcast_uuid = $_POST["call_broadcast_uuid"];
 	}
 
 	//check for all required data
@@ -161,131 +160,87 @@
 
 	//add or update the database
 	if ($_POST["persistformvar"] != "true") {
-		if ($action == "add" && permission_exists('call_broadcast_add')) {
-			$call_broadcast_uuid = uuid();
-			$sql = "insert into v_call_broadcasts ";
-			$sql .= "(";
-			$sql .= "domain_uuid, ";
-			$sql .= "call_broadcast_uuid, ";
-			$sql .= "broadcast_name, ";
-			$sql .= "broadcast_description, ";
-			$sql .= "broadcast_timeout, ";
-			$sql .= "broadcast_concurrent_limit, ";
-			//$sql .= "recording_uuid, ";
-			$sql .= "broadcast_caller_id_name, ";
-			$sql .= "broadcast_caller_id_number, ";
-			$sql .= "broadcast_destination_type, ";
-			$sql .= "broadcast_phone_numbers, ";
-			$sql .= "broadcast_avmd, ";
-			$sql .= "broadcast_destination_data, ";
-			$sql .= "broadcast_accountcode ";
-			$sql .= ")";
-			$sql .= "values ";
-			$sql .= "(";
-			$sql .= "'$domain_uuid', ";
-			$sql .= "'$call_broadcast_uuid', ";
-			$sql .= "'$broadcast_name', ";
-			$sql .= "'$broadcast_description', ";
-			if (strlen($broadcast_timeout) == 0) {
-				$sql .= "null, ";
-			}
-			else {
-				$sql .= "'$broadcast_timeout', ";
-			}
-			if (strlen($broadcast_concurrent_limit) == 0) {
-				$sql .= "null, ";
-			}
-			else {
-				$sql .= "'$broadcast_concurrent_limit', ";
-			}
-			//$sql .= "'$recording_uuid', ";
-			$sql .= "'$broadcast_caller_id_name', ";
-			$sql .= "'$broadcast_caller_id_number', ";
-			$sql .= "'$broadcast_destination_type', ";
-
-			//Add File selection and download sample 
- 		        $file_res = upload_file($sql,$broadcast_phone_numbers);
-			if ($file_res['code'] == true) {
-				$sql .= $file_res['sql'];
-			}
-			else {
-				$_SESSION["message_mood"] = "negative";
-				$_SESSION["message"] = $text['file-error'];
-				header("Location: call_broadcast_edit.php");
-				return false;
-			}
-			
-			$sql .= "'$broadcast_avmd', ";
-			$sql .= "'$broadcast_destination_data', ";
-			$sql .= "'$broadcast_accountcode' ";
-			$sql .= ")";
-			$db->exec(check_sql($sql));
-			unset($sql);
-
-			message::add($text['confirm-add']);
-			header("Location: call_broadcast.php");
-			return;
-		} //if ($action == "add")
-
-		if ($action == "update" && permission_exists('call_broadcast_edit')) {
-			$sql = "update v_call_broadcasts set ";
-			$sql .= "broadcast_name = '$broadcast_name', ";
-			$sql .= "broadcast_description = '$broadcast_description', ";
-			if (strlen($broadcast_timeout) == 0) {
-				$sql .= "broadcast_timeout = null, ";
-			}
-			else {
-				$sql .= "broadcast_timeout = '$broadcast_timeout', ";
-			}
-			if (strlen($broadcast_concurrent_limit) == 0) {
-				$sql .= "broadcast_concurrent_limit = null, ";
-			}
-			else {
-				$sql .= "broadcast_concurrent_limit = '$broadcast_concurrent_limit', ";
-			}
-			//$sql .= "recording_uuid = '$recording_uuid', ";
-			$sql .= "broadcast_caller_id_name = '$broadcast_caller_id_name', ";
-			$sql .= "broadcast_caller_id_number = '$broadcast_caller_id_number', ";
-			$sql .= "broadcast_destination_type = '$broadcast_destination_type', ";
-
-			//Update File selection and download sample 
-			$sql .= "broadcast_phone_numbers = "; 
-			$file_res = upload_file($sql,$broadcast_phone_numbers);
-			if ($file_res['code'] == true) {
-				$sql .= $file_res['sql'];
-			}
-			else {
-				$_SESSION["message_mood"] = "negative";
-				$_SESSION["message"] = $text['file-error'];
-				header("Location: call_broadcast_edit.php?id=".$_GET['id']);
-				return false;
-			}
-			
-			$sql .= "broadcast_avmd = '$broadcast_avmd', ";
-			$sql .= "broadcast_destination_data = '$broadcast_destination_data', ";
-			$sql .= "broadcast_accountcode = '$broadcast_accountcode' ";
-			$sql .= "where domain_uuid = '$domain_uuid' ";
-			$sql .= "and call_broadcast_uuid = '$call_broadcast_uuid'";
-			echo $sql."<br><br>";
-			$db->exec(check_sql($sql));
-			unset($sql);
-
... (diff truncated)
```
