# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 305_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `305_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php
$sub_menu = '100310';
include_once('./_common.php');

if ($w == "u" || $w == "d")
    check_demo();

if ($w == 'd')
    auth_check($auth[$sub_menu], "d");
else
    auth_check($auth[$sub_menu], "w");

check_admin_token();

$sql_common = " nw_device = '{$_POST['nw_device']}',
                nw_begin_time = '{$_POST['nw_begin_time']}',
                nw_end_time = '{$_POST['nw_end_time']}',
                nw_disable_hours = '{$_POST['nw_disable_hours']}',
                nw_left = '{$_POST['nw_left']}',
                nw_top = '{$_POST['nw_top']}',
                nw_height = '{$_POST['nw_height']}',
                nw_width = '{$_POST['nw_width']}',
                nw_subject = '{$_POST['nw_subject']}',
                nw_content = '{$_POST['nw_content']}',
                nw_content_html = '{$_POST['nw_content_html']}' ";

if($w == "")
{
    $sql = " insert {$g5['new_win_table']} set $sql_common ";
    sql_query($sql);

    $nw_id = sql_insert_id();
}
else if ($w == "u")
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,8 @@
 
 check_admin_token();
 
+$nw_subject = isset($_POST['nw_subject']) ? strip_tags($_POST['nw_subject']) : '';
+
 $sql_common = " nw_device = '{$_POST['nw_device']}',
                 nw_begin_time = '{$_POST['nw_begin_time']}',
                 nw_end_time = '{$_POST['nw_end_time']}',
@@ -20,7 +22,7 @@
                 nw_top = '{$_POST['nw_top']}',
                 nw_height = '{$_POST['nw_height']}',
                 nw_width = '{$_POST['nw_width']}',
-                nw_subject = '{$_POST['nw_subject']}',
+                nw_subject = '{$nw_subject}',
                 nw_content = '{$_POST['nw_content']}',
                 nw_content_html = '{$_POST['nw_content_html']}' ";
 
```
