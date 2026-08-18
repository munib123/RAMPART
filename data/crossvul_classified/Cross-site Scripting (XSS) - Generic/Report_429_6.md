# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 429_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `429_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-17 of the vulnerable file.

<?php
if (!defined('_GNUBOARD_')) exit; // 개별 페이지 접근 불가

// 게시판 관리의 상단 내용
if (G5_IS_MOBILE) {
    // 모바일의 경우 설정을 따르지 않는다.
    include_once(G5_BBS_PATH.'/_head.php');
    echo stripslashes($board['bo_mobile_content_head']);
} else {
    if(is_include_path_check($board['bo_include_head'])) {  //파일경로 체크
        @include ($board['bo_include_head']);
    } else {    //파일경로가 올바르지 않으면 기본파일을 가져옴
        include_once(G5_BBS_PATH.'/_head.php');
    }
    echo stripslashes($board['bo_content_head']);
}
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,13 +5,13 @@
 if (G5_IS_MOBILE) {
     // 모바일의 경우 설정을 따르지 않는다.
     include_once(G5_BBS_PATH.'/_head.php');
-    echo stripslashes($board['bo_mobile_content_head']);
+    echo html_purifier(stripslashes($board['bo_mobile_content_head']));
 } else {
     if(is_include_path_check($board['bo_include_head'])) {  //파일경로 체크
         @include ($board['bo_include_head']);
     } else {    //파일경로가 올바르지 않으면 기본파일을 가져옴
         include_once(G5_BBS_PATH.'/_head.php');
     }
-    echo stripslashes($board['bo_content_head']);
+    echo html_purifier(stripslashes($board['bo_content_head']));
 }
 ?>
```
