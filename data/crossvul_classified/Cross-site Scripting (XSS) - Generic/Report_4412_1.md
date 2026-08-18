# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4412_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4412_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-54 of the vulnerable file.

#
#  This program is released under the terms of the GNU General Public License as  
#  published by the Free Software Foundation, version 2 of the License. 
#  See license.txt.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#***************************************************************************************
error_reporting(0);
session_start();
include("functions/ParamLibFnc.php");
include("Data.php");
include("functions/DbGetFnc.php");
require_once("functions/PragRepFnc.php");

function db_start() {
    global $DatabaseServer, $DatabaseUsername, $DatabasePassword, $DatabaseName, $DatabasePort, $DatabaseType;

    switch ($DatabaseType) {
        case 'mysqli':
            $connection = new mysqli($DatabaseServer, $DatabaseUsername, $DatabasePassword, $DatabaseName);
            break;
    }

    // Error code for both.
    if ($connection === false) {
        switch ($DatabaseType) {
            case 'mysqli':
                $errormessage = mysqli_error($connection);
                break;
        }
        db_show_error("", "Could not Connect to Database: $DatabaseServer", $errstring);
    }
    return $connection;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,7 @@
 include("Data.php");
 include("functions/DbGetFnc.php");
 require_once("functions/PragRepFnc.php");
+include("AuthCryp.php");
 
 function db_start() {
     global $DatabaseServer, $DatabaseUsername, $DatabasePassword, $DatabaseName, $DatabasePort, $DatabaseType;
@@ -246,6 +247,7 @@
     die();
 }
 
+
 $log_msg = DBGet(DBQuery("SELECT MESSAGE FROM login_message WHERE DISPLAY='Y'"));
 if ($_REQUEST['pass_type_form'] == 'password') {
     if ($_REQUEST['pass_user_type'] == 'pass_student') {
@@ -401,12 +403,15 @@
 if ($_REQUEST['new_pass'] != '' && $_REQUEST['ver_pass'] != '') {
     $get_vals = explode(",", $_REQUEST['user_info']);
     $flag = 'submited_value';
-
-    $get_info = DBGet(DBQuery('SELECT COUNT(*) AS EX_REC FROM login_authentication WHERE user_id!=' . $get_vals[0] . ' AND profile_id!=' . $get_vals[1] . ' AND password=\'' . md5($_REQUEST['ver_pass']) . '\' '));
+    
+    $get_vals[0] = cryptor($get_vals[0], 'DEC', '');
+    $get_vals[1] = cryptor($get_vals[1], 'DEC', '');
+
+    $get_info = DBGet(DBQuery('SELECT COUNT(*) AS EX_REC FROM login_authentication WHERE user_id!=\'' . $get_vals[0] . '\' AND profile_id!=\'' . $get_vals[1] . '\' AND password=\'' . md5($_REQUEST['ver_pass']) . '\' '));
     if ($get_info[1]['EX_REC'] > 0) {
         $_SESSION['err_msg_mod'] = '<font color="red" ><b>Incorrect login credential.</b></font>';
     } else {
-        DBQuery('UPDATE login_authentication SET password=\'' . md5($_REQUEST['ver_pass']) . '\' WHERE user_id=' . $get_vals[0] . ' AND profile_id=' . $get_vals[1] . ' ');
+        DBQuery('UPDATE login_authentication SET password=\'' . md5($_REQUEST['ver_pass']) . '\' WHERE user_id=\'' . $get_vals[0] . '\' AND profile_id=\'' . $get_vals[1] . '\' ');
         $_SESSION['conf_msg'] = '<font color="red" ><b>Password updated successfully.</b></font>';
         echo'<script>window.location.href="index.php"</script>';
     }
@@ -495,17 +500,17 @@
                         <form name="f1" method="post" class="text-left" action="">
 
                             <?php if ($flag == 'stu_pass') { ?>
-                                <input type="hidden" name="user_info" value="<?php echo $stu_info[1]['STUDENT_ID'] . ',3,' . $_REQUEST['uname']; ?>"/>
+                                <input type="hidden" name="user_info" value="<?php echo cryptor($stu_info[1]['STUDENT_ID'], 'ENC', '') . ',' . cryptor('3', 'ENC', '') . ',' . $_REQUEST['uname']; ?>"/>
                                 <?php
                             }
                             if ($flag == 'stf_pass') {
                                 ?>
-                                <input type="hidden" name="user_info" value="<?php echo $stf_info[1]['STAFF_ID'] . ',' . $stf_info[1]['PROFILE_ID'] . ',' . $_REQUEST['uname']; ?>"/>
+                                <input type="hidden" name="user_info" value="<?php echo cryptor($stf_info[1]['STAFF_ID'], 'ENC', '') . ',' . cryptor($stf_info[1]['PROFILE_ID'], 'ENC', '') . ',' . $_REQUEST['uname']; ?>"/>
                                 <?php
                             }
                             if ($flag == 'par_pass') {
                                 ?>
-                                <input type="hidden" name="user_info" value="<?php echo $par_info[1]['STAFF_ID'] . ',' . $par_info[1]['PROFILE_ID'] . ',' . $_REQUEST['uname']; ?>"/>
+                                <input type="hidden" name="user_info" value="<?php echo cryptor($par_info[1]['STAFF_ID'], 'ENC', '') . ',' . cryptor($par_info[1]['PROFILE_ID'], 'ENC', '') . ',' . $_REQUEST['uname']; ?>"/>
                                 <?php
                             }
                             if ($flag == 'submited_value') {
```
