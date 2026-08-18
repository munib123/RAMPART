# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 2416_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2416_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 65-105 of the vulnerable file.

			}
			$result = queryDB($sql, array(TABLE_PREFIX, $id));

			if (isset($_REQUEST["en_id"]) && $_REQUEST["en_id"] <> "")
			{
				$msg->addFeedback('CONFIRM_GOOD');

				$member_id	= $id;
				require (AT_INCLUDE_PATH.'html/auto_enroll_courses.inc.php');
				unset($_SESSION['valid_user']);
				unset($_SESSION['member_id']);
				
				$table_title="
				<div class=\"row\">
					<h3>" . _AT('auto_enrolled_msg'). "<br /></h3>
				</div>";
		
				require(AT_INCLUDE_PATH.'header.inc.php');
				echo "<div class=\"input-form\">";
				require(AT_INCLUDE_PATH.'html/auto_enroll_list_courses.inc.php');
				echo '<p style="text-align:center"><a href="'. $_SERVER['PHP_SELF'] . '?auto_login=1&member_id='. $id .'">' . _AT("go_to_my_start_page") . '</a></p>';
				echo "</div>";
				require(AT_INCLUDE_PATH.'footer.inc.php');
				exit;
			}
			else
			{
				$msg->addFeedback('CONFIRM_GOOD');
				
				// enable auto login student into "my start page"
				$_REQUEST["auto_login"] = 1;
				$_REQUEST["member_id"] = $id;
			}
		} else {
			$msg->addError('CONFIRM_BAD');
		}
	} else {
		$msg->addError('CONFIRM_BAD');
	}
} else if (isset($_POST['submit'])) {
	$_POST['email'] = $addslashes($_POST['email']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,7 +82,7 @@
 				require(AT_INCLUDE_PATH.'header.inc.php');
 				echo "<div class=\"input-form\">";
 				require(AT_INCLUDE_PATH.'html/auto_enroll_list_courses.inc.php');
-				echo '<p style="text-align:center"><a href="'. $_SERVER['PHP_SELF'] . '?auto_login=1&member_id='. $id .'">' . _AT("go_to_my_start_page") . '</a></p>';
+				echo '<p style="text-align:center"><a href="'. $_SERVER['PHP_SELF'] . '?auto_login=1&member_id='. $id .'&code=' . $code .'">' . _AT("go_to_my_start_page") . '</a></p>';
 				echo "</div>";
 				require(AT_INCLUDE_PATH.'footer.inc.php');
 				exit;
@@ -94,6 +94,7 @@
 				// enable auto login student into "my start page"
 				$_REQUEST["auto_login"] = 1;
 				$_REQUEST["member_id"] = $id;
+				$_REQUEST["code"] = $code;
 			}
 		} else {
 			$msg->addError('CONFIRM_BAD');
@@ -142,8 +143,10 @@
 	
 	$sql = "SELECT M.member_id, M.login, M.preferences, M.language FROM %smembers M WHERE M.member_id=%d";
 	$row = queryDB($sql, array(TABLE_PREFIX, $_REQUEST["member_id"]), TRUE);
+
+	$code = substr(md5($e . $row['creation_date'] . $id), 0, 10);
 	
-	if ($row['member_id'] != '') 
+	if ($row['member_id'] != '' && isset($_REQUEST['code']) && $_REQUEST['code'] == $code) 
 	{
 		$_SESSION['valid_user'] = true;
 		$_SESSION['member_id']	= $_REQUEST["member_id"];
```
