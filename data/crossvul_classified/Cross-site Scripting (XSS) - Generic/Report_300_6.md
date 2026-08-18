# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 300_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `300_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-40 of the vulnerable file.

<?php
$sub_menu = '300700';
include_once('./_common.php');

if ($w == "u" || $w == "d")
    check_demo();

if ($W == 'd')
    auth_check($auth[$sub_menu], "d");
else
    auth_check($auth[$sub_menu], "w");

check_admin_token();

@mkdir(G5_DATA_PATH."/faq", G5_DIR_PERMISSION);
@chmod(G5_DATA_PATH."/faq", G5_DIR_PERMISSION);

if ($fm_himg_del)  @unlink(G5_DATA_PATH."/faq/{$fm_id}_h");
if ($fm_timg_del)  @unlink(G5_DATA_PATH."/faq/{$fm_id}_t");

$sql_common = " set fm_subject = '$fm_subject',
                    fm_head_html = '$fm_head_html',
                    fm_tail_html = '$fm_tail_html',
                    fm_mobile_head_html = '$fm_mobile_head_html',
                    fm_mobile_tail_html = '$fm_mobile_tail_html',
                    fm_order = '$fm_order' ";

if ($w == "")
{
    $sql = " alter table {$g5['faq_master_table']} auto_increment=1 ";
    sql_query($sql);

    $sql = " insert {$g5['faq_master_table']} $sql_common ";
    sql_query($sql);

    $fm_id = sql_insert_id();
}
else if ($w == "u")
{
    $sql = " update {$g5['faq_master_table']} $sql_common where fm_id = '$fm_id' ";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,8 @@
 
 if ($fm_himg_del)  @unlink(G5_DATA_PATH."/faq/{$fm_id}_h");
 if ($fm_timg_del)  @unlink(G5_DATA_PATH."/faq/{$fm_id}_t");
+
+$fm_subject = strip_tags($fm_subject);
 
 $sql_common = " set fm_subject = '$fm_subject',
                     fm_head_html = '$fm_head_html',
```
