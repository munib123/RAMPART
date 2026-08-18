# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 301_10
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `301_10`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.

include_once("./_common.php");

auth_check($auth[$sub_menu], "w");

$g5['title'] = "휴대폰번호 업데이트";

$g5['sms5_demo'] = 0;

$is_hp_exist = false;

$bk_hp = get_hp($bk_hp);

if ($w=='u') // 업데이트
{
    if (!$bg_no) $bg_no = 0;

    if (!$bk_receipt) $bk_receipt = 0; else $bk_receipt = 1;

    if (!strlen(trim($bk_name)))
        alert('이름을 입력해주세요');

    if ($bk_hp == '')
        alert('휴대폰번호만 입력 가능합니다.');
/*
    $res = sql_fetch("select * from {$g5['sms5_book_table']} where bk_no<>'$bk_no' and bk_hp='$bk_hp'");
    if ($res)
        alert('같은 번호가 존재합니다.');
*/
    $res = sql_fetch("select * from {$g5['sms5_book_table']} where bk_no='$bk_no'");
    if (!$res)
        alert('존재하지 않는 데이터 입니다.');

    if ($bg_no != $res['bg_no']) {
        if ($res['mb_id']) $mem = "bg_member"; else $mem = "bg_nomember";
        if ($res['bk_receipt'] == 1) $sms = "bg_receipt"; else $sms = "bg_reject";
        sql_query("update {$g5['sms5_book_group_table']} set bg_count = bg_count - 1, $mem = $mem - 1, $sms = $sms - 1 where bg_no='{$res['bg_no']}'");
        sql_query("update {$g5['sms5_book_group_table']} set bg_count = bg_count + 1, $mem = $mem + 1, $sms = $sms + 1 where bg_no='$bg_no'");
    }

    if ($bk_receipt != $res['bk_receipt']) {
        if ($bk_receipt == 1)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,8 @@
 
     if (!strlen(trim($bk_name)))
         alert('이름을 입력해주세요');
+
+    $bk_name = strip_tags($bk_name);
 
     if ($bk_hp == '')
         alert('휴대폰번호만 입력 가능합니다.');
```
