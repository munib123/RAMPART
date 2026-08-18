# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 302_11
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `302_11`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 13-53 of the vulnerable file.

if ($w == 'u' && is_numeric($bk_no)) {
    $write = sql_fetch("select * from {$g5['sms5_book_table']} where bk_no='$bk_no'");
    if (!$write)
        alert('데이터가 없습니다.');

    if ($write['mb_id']) {
        $res = sql_fetch("select mb_id from {$g5['member_table']} where mb_id='{$write['mb_id']}'");
        $write['mb_id'] = $res['mb_id'];
        $sql = "select mb_id from {$g5['member_table']} where mb_hp = '{$write['bk_hp']}' and mb_id <> '{$write['mb_id']}' and mb_hp <> '' ";
        $result = sql_query($sql);
        while($tmp = sql_fetch_array($result)){
            $exist_hplist[] = $tmp;
        }
        $exist_msg_1 = '(수정시 회원정보에 반영되지 않습니다.)';
        $exist_msg_2 = '(수정시 회원정보에 반영됩니다.)';
        $exist_msg = count($exist_hplist) ? $exist_msg_1 : $exist_msg_2;
    }
    $g5['title'] .= '수정';
}
else  {
    $write['bg_no'] = $bg_no;
    $g5['title'] .= '추가';
}

if (!is_numeric($write['bk_receipt']))
    $write['bk_receipt'] = 1;

$no_group = sql_fetch("select * from {$g5['sms5_book_group_table']} where bg_no = 1");

include_once(G5_ADMIN_PATH."/admin.head.php");
?>

<form name="book_form" id="book_form" method="post" action="./num_book_update.php">
<input type="hidden" name="w" value="<?php echo get_sanitize_input($w); ?>">
<input type="hidden" name="page" value="<?php echo get_sanitize_input($page); ?>">
<input type="hidden" name="ap" value="<?php echo get_sanitize_input($ap); ?>">
<input type="hidden" name="bk_no" value="<?php echo $write['bk_no']?>">
<input type="hidden" name="mb_id" id="mb_id" value="<?php echo $write['mb_id']?>">
<input type="hidden" name="get_bg_no" value="<?php echo get_sanitize_input($bg_no); ?>">

<div class="tbl_frm01 tbl_wrap">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,7 @@
     $g5['title'] .= '수정';
 }
 else  {
-    $write['bg_no'] = $bg_no;
+    $write = array('bg_no' => (int) $bg_no);
     $g5['title'] .= '추가';
 }
 
@@ -74,7 +74,7 @@
     </tr>
     <tr>
         <th scope="row"><label for="bk_name">이름<strong class="sound_only"> 필수</strong></label></th>
-        <td><input type="text" name="bk_name" id="bk_name" maxlength="50" value="<?php echo $write['bk_name']?>" required class="frm_input required"></td>
+        <td><input type="text" name="bk_name" id="bk_name" maxlength="50" value="<?php echo get_sanitize_input($write['bk_name']); ?>" required class="frm_input required"></td>
     </tr>
     <tr>
         <th scope="row"><label for="bk_hp">휴대폰번호<strong class="sound_only"> 필수</strong></label></th>
```
