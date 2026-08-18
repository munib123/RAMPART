# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 429_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `429_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 54-94 of the vulnerable file.


$board_path = G5_DATA_PATH.'/file/'.$bo_table;

// 게시판 디렉토리 생성
@mkdir($board_path, G5_DIR_PERMISSION);
@chmod($board_path, G5_DIR_PERMISSION);

// 디렉토리에 있는 파일의 목록을 보이지 않게 한다.
$file = $board_path . '/index.php';
$f = @fopen($file, 'w');
@fwrite($f, '');
@fclose($f);
@chmod($file, G5_FILE_PERMISSION);

// 분류에 & 나 = 는 사용이 불가하므로 2바이트로 바꾼다.
$src_char = array('&', '=');
$dst_char = array('＆', '〓');
$bo_category_list = str_replace($src_char, $dst_char, $bo_category_list);
//https://github.com/gnuboard/gnuboard5/commit/f5f4925d4eb28ba1af728e1065fc2bdd9ce1da58 에 따른 조치
$str_bo_category_list = isset($_POST['bo_category_list']) ? preg_replace("/[\<\>\'\"\\\'\\\"\%\=\(\)\/\^\*]/", "", $_POST['bo_category_list']) : '';

$sql_common = " gr_id               = '{$_POST['gr_id']}',
                bo_subject          = '{$_POST['bo_subject']}',
                bo_mobile_subject   = '{$_POST['bo_mobile_subject']}',
                bo_device           = '{$_POST['bo_device']}',
                bo_admin            = '{$_POST['bo_admin']}',
                bo_list_level       = '{$_POST['bo_list_level']}',
                bo_read_level       = '{$_POST['bo_read_level']}',
                bo_write_level      = '{$_POST['bo_write_level']}',
                bo_reply_level      = '{$_POST['bo_reply_level']}',
                bo_comment_level    = '{$_POST['bo_comment_level']}',
                bo_html_level       = '{$_POST['bo_html_level']}',
                bo_link_level       = '{$_POST['bo_link_level']}',
                bo_count_modify     = '{$_POST['bo_count_modify']}',
                bo_count_delete     = '{$_POST['bo_count_delete']}',
                bo_upload_level     = '{$_POST['bo_upload_level']}',
                bo_download_level   = '{$_POST['bo_download_level']}',
                bo_read_point       = '{$_POST['bo_read_point']}',
                bo_write_point      = '{$_POST['bo_write_point']}',
                bo_comment_point    = '{$_POST['bo_comment_point']}',
                bo_download_point   = '{$_POST['bo_download_point']}',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,6 +71,9 @@
 $bo_category_list = str_replace($src_char, $dst_char, $bo_category_list);
 //https://github.com/gnuboard/gnuboard5/commit/f5f4925d4eb28ba1af728e1065fc2bdd9ce1da58 에 따른 조치
 $str_bo_category_list = isset($_POST['bo_category_list']) ? preg_replace("/[\<\>\'\"\\\'\\\"\%\=\(\)\/\^\*]/", "", $_POST['bo_category_list']) : '';
+
+$_POST['bo_subject'] = strip_tags($_POST['bo_subject']);
+$_POST['bo_mobile_subject'] = strip_tags($_POST['bo_mobile_subject']);
 
 $sql_common = " gr_id               = '{$_POST['gr_id']}',
                 bo_subject          = '{$_POST['bo_subject']}',
```
