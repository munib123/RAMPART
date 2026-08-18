# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 305_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `305_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.

include_once('./_common.php');

if ($w == "u" || $w == "d")
    check_demo();

if ($w == 'd')
    auth_check($auth[$sub_menu], "d");
else
    auth_check($auth[$sub_menu], "w");

check_admin_token();

if ($w == "" || $w == "u")
{
    if(preg_match("/[^a-z0-9_]/i", $co_id)) alert("ID 는 영문자, 숫자, _ 만 가능합니다.");

    $sql = " select * from {$g5['content_table']} where co_id = '$co_id' ";
    $co_row = sql_fetch($sql);
}

$co_include_head = preg_replace(array("#[\\\]+$#", "#(<\?php|<\?)#i"), "", substr($co_include_head, 0, 255));
$co_include_tail = preg_replace(array("#[\\\]+$#", "#(<\?php|<\?)#i"), "", substr($co_include_tail, 0, 255));

// 관리자가 자동등록방지를 사용해야 할 경우
if (($co_row['co_include_head'] !== $co_include_head || $co_row['co_include_tail'] !== $co_include_tail) && function_exists('get_admin_captcha_by') && get_admin_captcha_by()){
    include_once(G5_CAPTCHA_PATH.'/captcha.lib.php');

    if (!chk_captcha()) {
        alert('자동등록방지 숫자가 틀렸습니다.');
    }
}

@mkdir(G5_DATA_PATH."/content", G5_DIR_PERMISSION);
@chmod(G5_DATA_PATH."/content", G5_DIR_PERMISSION);

if ($co_himg_del)  @unlink(G5_DATA_PATH."/content/{$co_id}_h");
if ($co_timg_del)  @unlink(G5_DATA_PATH."/content/{$co_id}_t");

$error_msg = '';

if( $co_include_head ){
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,7 @@
     $co_row = sql_fetch($sql);
 }
 
+$co_subject = strip_tags($co_subject);
 $co_include_head = preg_replace(array("#[\\\]+$#", "#(<\?php|<\?)#i"), "", substr($co_include_head, 0, 255));
 $co_include_tail = preg_replace(array("#[\\\]+$#", "#(<\?php|<\?)#i"), "", substr($co_include_tail, 0, 255));
 
```
