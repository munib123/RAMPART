# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 808_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `808_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 64-123 of the vulnerable file.

// 		//authorized;
// 	} elseif (stristr($switch_cmd, 'uuid_record') == true) {
// 		//authorized;
// 	} elseif (stristr($action, 'user_status') == true) {
// 		//authorized;
// 	} elseif (stristr($action, 'callcenter_config') == true) {
// 		//authorized;
// 	} elseif (stristr($action, 'originate') == true) {
// 		//authorized;
// 	} else {
// 		//not found. this command is not authorized
// 		echo "access denied";
// 		exit;
// 	}

if (count($_GET)>0) {

	//setup the event socket connection
		$fp = event_socket_create($_SESSION['event_socket_ip_address'], $_SESSION['event_socket_port'], $_SESSION['event_socket_password']);

	if (stristr($action, 'user_status') == true) {
		$user_status = $data;
		switch ($user_status) {
		case "Available":
			$user_status = "Available";
			//update the user state
			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
			$response = event_socket_request($fp, $cmd);
			break;
		case "Available_On_Demand":
			$user_status = "Available (On Demand)";
			//update the user state
			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
			$response = event_socket_request($fp, $cmd);
			break;
		case "Logged_Out":
			$user_status = "Logged Out";
			//update the user state
			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
			$response = event_socket_request($fp, $cmd);
			break;
		case "On_Break":
			$user_status = "On Break";
			//update the user state
			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
			$response = event_socket_request($fp, $cmd);
			break;
		case "Do_Not_Disturb":
			$user_status = "Do Not Disturb";
			//update the user state
			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
			$response = event_socket_request($fp, $cmd);
			break;
		default:
			$user_status = "";
		}
	}

	//fs cmd
	if (strlen($switch_cmd) > 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,104 +81,123 @@
 	//setup the event socket connection
 		$fp = event_socket_create($_SESSION['event_socket_ip_address'], $_SESSION['event_socket_port'], $_SESSION['event_socket_password']);
 
-	if (stristr($action, 'user_status') == true) {
-		$user_status = $data;
-		switch ($user_status) {
-		case "Available":
-			$user_status = "Available";
-			//update the user state
-			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
-			$response = event_socket_request($fp, $cmd);
-			break;
-		case "Available_On_Demand":
-			$user_status = "Available (On Demand)";
-			//update the user state
-			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
-			$response = event_socket_request($fp, $cmd);
-			break;
-		case "Logged_Out":
-			$user_status = "Logged Out";
-			//update the user state
-			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
-			$response = event_socket_request($fp, $cmd);
-			break;
-		case "On_Break":
-			$user_status = "On Break";
-			//update the user state
-			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
-			$response = event_socket_request($fp, $cmd);
-			break;
-		case "Do_Not_Disturb":
-			$user_status = "Do Not Disturb";
-			//update the user state
-			$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
-			$response = event_socket_request($fp, $cmd);
-			break;
-		default:
-			$user_status = "";
+	//get the status
+		if (stristr($action, 'user_status') == true) {
+			$user_status = $data;
+			switch ($user_status) {
+			case "Available":
+				$user_status = "Available";
+				//update the user state
+				$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
+				$response = event_socket_request($fp, $cmd);
+				break;
+			case "Available_On_Demand":
+				$user_status = "Available (On Demand)";
+				//update the user state
+				$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
+				$response = event_socket_request($fp, $cmd);
+				break;
+			case "Logged_Out":
+				$user_status = "Logged Out";
+				//update the user state
+				$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
+				$response = event_socket_request($fp, $cmd);
+				break;
+			case "On_Break":
+				$user_status = "On Break";
+				//update the user state
+				$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
+				$response = event_socket_request($fp, $cmd);
+				break;
+			case "Do_Not_Disturb":
+				$user_status = "Do Not Disturb";
+				//update the user state
+				$cmd = "api callcenter_config agent set state ".$username."@".$_SESSION['domain_name']." Waiting";
+				$response = event_socket_request($fp, $cmd);
+				break;
+			default:
+				$user_status = "";
+			}
 		}
-	}
-
-	//fs cmd
-	if (strlen($switch_cmd) > 0) {
-
-		//set the status so they are compatible with mod_callcenter
+
+	//allow specific commands
+		if (strlen($switch_cmd) > 0) {
+			if (stristr($switch_cmd, 'originate') == true) {}
+			elseif (stristr($switch_cmd, 'uuid_record') == true) {}
+			elseif (stristr($switch_cmd, 'uuid_transfer') == true) {}
+			elseif (stristr($switch_cmd, 'eavesdrop') == true) {}
+			elseif (stristr($switch_cmd, 'uuid_kill') == true) {}
+			else {
+				$switch_cmd = '';
+			}
+			if (stristr($switch_cmd, 'system') == true) {
+				$switch_cmd = '';
+			}
+		}
+
+	//switch cmd
+		if (strlen($switch_cmd) > 0) {
+
+			//set the status so they are compatible with mod_callcenter
 			$switch_cmd = str_replace("Available_On_Demand", "'Available (On Demand)'", $switch_cmd);
 			$switch_cmd = str_replace("Logged_Out", "'Logged Out'", $switch_cmd);
 			$switch_cmd = str_replace("On_Break", "'On Break'", $switch_cmd);
 			$switch_cmd = str_replace("Do_Not_Disturb", "'Logged Out'", $switch_cmd);
 
-		/*
-		//if ($action == "energy") {
-			//conference 3001-example.org energy 103
+			/*
+			//if ($action == "energy") {
+				//conference 3001-example.org energy 103
+				$switch_result = event_socket_request($fp, 'api '.$switch_cmd);
+				$result_array = explode("=",$switch_result);
+				$tmp_value = $result_array[1];
+				//if ($direction == "up") { $tmp_value = $tmp_value + 100; }
+				//if ($direction == "down") { $tmp_value = $tmp_value - 100; }
+				//echo "energy $tmp_value<br />\n";
+				$switch_result = event_socket_request($fp, 'api '.$switch_cmd.' '.$tmp_value);
+			//}
+			if ($action == "volume_in") {
+				$switch_result = event_socket_request($fp, 'api '.$switch_cmd);
+				$result_array = explode("=",$switch_result);
+				$tmp_value = $result_array[1];
+				if ($direction == "up") { $tmp_value = $tmp_value + 1; }
+				if ($direction == "down") { $tmp_value = $tmp_value - 1; }
+				//echo "volume $tmp_value<br />\n";
+				$switch_result = event_socket_request($fp, 'api '.$switch_cmd.' '.$tmp_value);
+			}
+			if ($action == "volume_out") {
+				$switch_result = event_socket_request($fp, 'api '.$switch_cmd);
+				$result_array = explode("=",$switch_result);
+				$tmp_value = $result_array[1];
+				if ($direction == "up") { $tmp_value = $tmp_value + 1; }
+				if ($direction == "down") { $tmp_value = $tmp_value - 1; }
+				//echo "volume $tmp_value<br />\n";
+				$switch_result = event_socket_request($fp, 'api '.$switch_cmd.' '.$tmp_value);
+			}
+			*/
+
+			//run the command
 			$switch_result = event_socket_request($fp, 'api '.$switch_cmd);
-			$result_array = explode("=",$switch_result);
-			$tmp_value = $result_array[1];
-			//if ($direction == "up") { $tmp_value = $tmp_value + 100; }
-			//if ($direction == "down") { $tmp_value = $tmp_value - 100; }
-			//echo "energy $tmp_value<br />\n";
-			$switch_result = event_socket_request($fp, 'api '.$switch_cmd.' '.$tmp_value);
-		//}
-		if ($action == "volume_in") {
-			$switch_result = event_socket_request($fp, 'api '.$switch_cmd);
-			$result_array = explode("=",$switch_result);
-			$tmp_value = $result_array[1];
-			if ($direction == "up") { $tmp_value = $tmp_value + 1; }
-			if ($direction == "down") { $tmp_value = $tmp_value - 1; }
-			//echo "volume $tmp_value<br />\n";
-			$switch_result = event_socket_request($fp, 'api '.$switch_cmd.' '.$tmp_value);
+
+			//record stop
+			if ($action == "record") {
+				if (trim($_GET["action2"]) == "stop") {
+					$x=0;
+					while (true) {
+						if ($x > 0) {
+							$dest_file = $_SESSION['switch']['recordings']['dir']."/archive/".date("Y")."/".date("M")."/".date("d")."/".$_GET["uuid"]."_".$x.".wav";
+						}
+						else {
+							$dest_file = $_SESSION['switch']['recordings']['dir']."/archive/".date("Y")."/".date("M")."/".date("d")."/".$_GET["uuid"].".wav";
+						}
+						if (!file_exists($dest_file)) {
+							rename($_SESSION['switch']['recordings']['dir']."/archive/".date("Y")."/".date("M")."/".date("d")."/".$_GET["uuid"].".wav", $dest_file);
+							break;
+						}
+						$x++;
+					}
+				}
+			}
 		}
-		if ($action == "volume_out") {
-			$switch_result = event_socket_request($fp, 'api '.$switch_cmd);
-			$result_array = explode("=",$switch_result);
-			$tmp_value = $result_array[1];
-			if ($direction == "up") { $tmp_value = $tmp_value + 1; }
-			if ($direction == "down") { $tmp_value = $tmp_value - 1; }
-			//echo "volume $tmp_value<br />\n";
-			$switch_result = event_socket_request($fp, 'api '.$switch_cmd.' '.$tmp_value);
-		}
-		*/
-
-		$switch_result = event_socket_request($fp, 'api '.$switch_cmd);
-		if ($action == "record") {
-			if (trim($_GET["action2"]) == "stop") {
-				$x=0;
-				while (true) {
-					if ($x > 0) {
-						$dest_file = $_SESSION['switch']['recordings']['dir']."/archive/".date("Y")."/".date("M")."/".date("d")."/".$_GET["uuid"]."_".$x.".wav";
-					}
-					else {
... (diff truncated)
```
