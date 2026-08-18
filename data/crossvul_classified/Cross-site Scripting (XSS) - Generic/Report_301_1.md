# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 301_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `301_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php
$sub_menu = "300200";
include_once('./_common.php');

if ($w == 'u')
    check_demo();

auth_check($auth[$sub_menu], 'w');

if ($is_admin != 'super' && $w == '') alert('최고관리자만 접근 가능합니다.');

check_admin_token();

if (!preg_match("/^([A-Za-z0-9_]{1,10})$/", $_POST['gr_id']))
    alert('그룹 ID는 공백없이 영문자, 숫자, _ 만 사용 가능합니다. (10자 이내)');

if (!$gr_subject) alert('그룹 제목을 입력하세요.');

$sql_common = " gr_subject = '{$_POST['gr_subject']}',
                gr_device = '{$_POST['gr_device']}',
                gr_admin  = '{$_POST['gr_admin']}',
                gr_1_subj = '{$_POST['gr_1_subj']}',
                gr_2_subj = '{$_POST['gr_2_subj']}',
                gr_3_subj = '{$_POST['gr_3_subj']}',
                gr_4_subj = '{$_POST['gr_4_subj']}',
                gr_5_subj = '{$_POST['gr_5_subj']}',
                gr_6_subj = '{$_POST['gr_6_subj']}',
                gr_7_subj = '{$_POST['gr_7_subj']}',
                gr_8_subj = '{$_POST['gr_8_subj']}',
                gr_9_subj = '{$_POST['gr_9_subj']}',
                gr_10_subj = '{$_POST['gr_10_subj']}',
                gr_1 = '{$_POST['gr_1']}',
                gr_2 = '{$_POST['gr_2']}',
                gr_3 = '{$_POST['gr_3']}',
                gr_4 = '{$_POST['gr_4']}',
                gr_5 = '{$_POST['gr_5']}',
                gr_6 = '{$_POST['gr_6']}',
                gr_7 = '{$_POST['gr_7']}',
                gr_8 = '{$_POST['gr_8']}',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,7 +16,9 @@
 
 if (!$gr_subject) alert('그룹 제목을 입력하세요.');
 
-$sql_common = " gr_subject = '{$_POST['gr_subject']}',
+$gr_subject = isset($_POST['gr_subject']) ? strip_tags($_POST['gr_subject']) : '';
+
+$sql_common = " gr_subject = '{$gr_subject}',
                 gr_device = '{$_POST['gr_device']}',
                 gr_admin  = '{$_POST['gr_admin']}',
                 gr_1_subj = '{$_POST['gr_1_subj']}',
```
