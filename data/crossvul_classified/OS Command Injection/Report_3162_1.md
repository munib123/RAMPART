# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3162_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3162_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 46-86 of the vulnerable file.

   		case "ok":
   			$alert_type = "success";
			$alert_icon = "fa-check-circle";
			break;
		default:
			$alert_type = "info";
			$alert_icon = "fa-info-circle";
			break;
	}

	// Display the message
	echo "<p class='alert alert-dismissible alert-".$alert_type." fade in'>
			<button type='button' class='close' data-dismiss='alert' aria-label='Close'>
			  <span aria-hidden='true'>&times;</span>
			</button>
			<i class='fa ".$alert_icon."'></i> $tempid $text
		  </p>";
}

// Connect to Database
function sqlrequest($database,$sql,$id=false){

	// Get the global value
	global $database_host;
	global $database_username;
	global $database_password;

	$connexion = mysqli_connect($database_host, $database_username, $database_password, $database);
	if (!$connexion) {
		echo "<ul>";
		echo "<li class='msg_title'>Alert EyesOfNetwork - Message EON-database connect</li>";
		echo "<li class='msg'> Could not connect to database : $database ($database_host)</li>";
		echo "</ul>";
		exit(1);
	}

	if ( $database == "eonweb" ) {
		// Force UTF-8
		mysqli_query($connexion, "SET NAMES 'utf8'");
	}
	$result=mysqli_query($connexion, "$sql");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,7 @@
 }
 
 // Connect to Database
-function sqlrequest($database,$sql,$id=false){
+function sqlrequest($database,$sql,$id=false,$prepare=false){
 
 	// Get the global value
 	global $database_host;
@@ -83,8 +83,22 @@
 		// Force UTF-8
 		mysqli_query($connexion, "SET NAMES 'utf8'");
 	}
-	$result=mysqli_query($connexion, "$sql");
-
+	
+	if(is_array($prepare)) {
+		$stmt = mysqli_prepare($connexion,$sql);
+		
+		if(isset($prepare[0]) && isset($prepare[1])) {
+			$ref = new ReflectionClass('mysqli_stmt');
+			$method = $ref->getMethod("bind_param");
+			$method->invokeArgs($stmt,$prepare);
+		}
+		
+		mysqli_stmt_execute($stmt);
+		$result = mysqli_stmt_get_result($stmt);
+	} else {
+		$result=mysqli_query($connexion, "$sql");
+	}
+		
 	if($id==true)
 		$result=mysqli_insert_id($connexion);
 		
```
