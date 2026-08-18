# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 5833_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5833_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 1-51 of the vulnerable file.

<?php

//Burden, Copyright Josh Fradley (http://github.com/joshf/Burden)

if (!file_exists("config.php")) {
    die("Error: Config file not found! Please reinstall Burden.");
}

require_once("config.php");

session_start();

//Connect to database
@$con = mysql_connect(DB_HOST, DB_USER, DB_PASSWORD);
if (!$con) {
    die("Error: Could not connect to database (" . mysql_error() . "). Check your database settings are correct.");
}

mysql_select_db(DB_NAME, $con);
    
//If cookie is set, skip login
if (isset($_COOKIE["burden_user_rememberme"])) {
    $id = $_COOKIE["burden_user_rememberme"];
    $getid = mysql_query("SELECT `id` FROM `Users` WHERE `id` = \"$id\"");
    if (mysql_num_rows($getid) == 0) {
        header("Location: logout.php");
        exit;
    }
    $userinforesult = mysql_fetch_assoc($getid); 
    $_SESSION["burden_user"] = $userinforesult["id"];
}

if (isset($_POST["password"]) && isset($_POST["username"])) {
    $username = mysql_real_escape_string($_POST["username"]);
    $password = $_POST["password"];
    $userinfo = mysql_query("SELECT `id`, `user`, `password`, `salt` FROM `Users` WHERE `user` = \"$username\"");
    $userinforesult = mysql_fetch_assoc($userinfo);
    if (mysql_num_rows($userinfo) == 0) {
        header("Location: login.php?user_doesnt_exist=true");
        exit;
    }
    $salt = $userinforesult["salt"];
    $hashedpassword = hash("sha256", $salt . hash("sha256", $password));
    if ($hashedpassword == $userinforesult["password"]) {
        $_SESSION["burden_user"] = $userinforesult["id"];
        if (isset($_POST["rememberme"])) {
            setcookie("burden_user_rememberme", $userinforesult["id"], time()+1209600);
        }
    } else {
        header("Location: login.php?login_error=true");
        exit;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,18 +17,6 @@
 }
 
 mysql_select_db(DB_NAME, $con);
-    
-//If cookie is set, skip login
-if (isset($_COOKIE["burden_user_rememberme"])) {
-    $id = $_COOKIE["burden_user_rememberme"];
-    $getid = mysql_query("SELECT `id` FROM `Users` WHERE `id` = \"$id\"");
-    if (mysql_num_rows($getid) == 0) {
-        header("Location: logout.php");
-        exit;
-    }
-    $userinforesult = mysql_fetch_assoc($getid); 
-    $_SESSION["burden_user"] = $userinforesult["id"];
-}
 
 if (isset($_POST["password"]) && isset($_POST["username"])) {
     $username = mysql_real_escape_string($_POST["username"]);
@@ -123,13 +111,6 @@
 <input type="password" id="password" name="password" class="input-block-level" placeholder="Password...">
 </div>
 </div>
-<div class="control-group">
-<div class="controls">
-<label class="checkbox">
-<input type="checkbox" id="rememberme" name="rememberme"> Remember Me
-</label>
-</div>
-</div>
 <button type="submit" class="btn pull-right">Login</button>
 </fieldset>
 </form>
```
