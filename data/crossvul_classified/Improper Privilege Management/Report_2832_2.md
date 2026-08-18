# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 2832_2
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2832_2`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 100-140 of the vulnerable file.


// Prepare superGlobal variables
$session_user_language =        $superGlobal->get("user_language", "SESSION");
$session_user_id =              $superGlobal->get("user_id", "SESSION");
$session_user_flag =            $superGlobal->get("user_language_flag", "SESSION");
$session_user_admin =           $superGlobal->get("user_admin", "SESSION");
$session_user_avatar_thumb =    $superGlobal->get("user_avatar_thumb", "SESSION");
$session_name =                 $superGlobal->get("name", "SESSION");
$session_lastname =             $superGlobal->get("lastname", "SESSION");
$session_user_manager =         $superGlobal->get("user_manager", "SESSION");
$session_user_read_only =       $superGlobal->get("user_read_only", "SESSION");
$session_is_admin =             $superGlobal->get("is_admin", "SESSION");
$session_login =                $superGlobal->get("login", "SESSION");
$session_validite_pw =          $superGlobal->get("validite_pw", "SESSION");
$session_nb_folders =           $superGlobal->get("nb_folders", "SESSION");
$session_nb_roles =             $superGlobal->get("nb_roles", "SESSION");
$session_autoriser =            $superGlobal->get("autoriser", "SESSION");
$session_hide_maintenance =     $superGlobal->get("hide_maintenance", "SESSION");
$session_initial_url =          $superGlobal->get("initial_url", "SESSION");
$server_request_uri =           $superGlobal->get("REQUEST_URI", "SERVER");


/* DEFINE WHAT LANGUAGE TO USE */
if (isset($_GET['language']) === true) {
    // case of user has change language in the login page
    $dataLanguage = DB::queryFirstRow(
        "SELECT flag, name
        FROM ".prefix_table("languages")."
        WHERE name = %s",
        filter_var($_GET['language'], FILTER_SANITIZE_STRING)
    );
    $superGlobal->put("user_language", $dataLanguage['name'], "SESSION");
    $superGlobal->put("user_language_flag", $dataLanguage['flag'], "SESSION");
} elseif ($session_user_id === null && null === $post_language && $session_user_language === null) {
    //get default language
    $dataLanguage = DB::queryFirstRow(
        "SELECT m.valeur AS valeur, l.flag AS flag
        FROM ".prefix_table("misc")." AS m
        INNER JOIN ".prefix_table("languages")." AS l ON (m.valeur = l.name)
        WHERE m.type=%s_type AND m.intitule=%s_intitule",
        array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,6 +117,7 @@
 $session_hide_maintenance =     $superGlobal->get("hide_maintenance", "SESSION");
 $session_initial_url =          $superGlobal->get("initial_url", "SESSION");
 $server_request_uri =           $superGlobal->get("REQUEST_URI", "SERVER");
+$session_nb_users_online =        $superGlobal->get("nb_users_online", "SESSION");
 
 
 /* DEFINE WHAT LANGUAGE TO USE */
@@ -783,7 +784,7 @@
             <a href="https://www.reddit.com/r/TeamPass/" target="_blank" style="color:#F0F0F0;" class="tip" title="'.addslashes($LANG['admin_help']).'"><i class="fa fa-reddit-alien"></i></a>
         </div>
         <div style="float:left;width:32%;text-align:center;">
-            ', ($session_user_id !== null && empty($session_user_id) === false) ? '<i class="fa fa-users"></i>&nbsp;'.$_SESSION['nb_users_online'].'&nbsp;'.$LANG['users_online'].'&nbsp;|&nbsp;<i class="fa fa-hourglass-end"></i>&nbsp;'.$LANG['index_expiration_in'].'&nbsp;<div style="display:inline;" id="countdown"></div>' : '', '
+            ', ($session_user_id !== null && empty($session_user_id) === false) ? '<i class="fa fa-users"></i>&nbsp;'.$session_nb_users_online.'&nbsp;'.$LANG['users_online'].'&nbsp;|&nbsp;<i class="fa fa-hourglass-end"></i>&nbsp;'.$LANG['index_expiration_in'].'&nbsp;<div style="display:inline;" id="countdown"></div>' : '', '
         </div><div id="countdown2"></div>
         <div style="float:right;text-align:right;">
             <i class="fa fa-clock-o"></i>&nbsp;'. $LANG['server_time']." : ".@date($SETTINGS['date_format'], (string) $_SERVER['REQUEST_TIME'])." - ".@date($SETTINGS['time_format'], (string) $_SERVER['REQUEST_TIME']).'
```
