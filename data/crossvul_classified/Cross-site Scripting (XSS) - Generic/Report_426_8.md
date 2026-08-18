# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 426_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `426_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 26-64 of the vulnerable file.

        else {
            $action = https_url(G5_BBS_DIR).'/password_check.php';
            $return_url = G5_HTTP_BBS_URL.'/board.php?bo_table='.$bo_table;
        }
        break;
    case 'sc' :
        // 비밀번호 창에서 로그인 하는 경우 관리자 또는 자신의 글이면 바로 글보기로 감
        if ($is_admin || ($member['mb_id'] == $write['mb_id'] && $write['mb_id']))
            goto_url(G5_HTTP_BBS_URL.'/board.php?bo_table='.$bo_table.'&amp;wr_id='.$wr_id);
        else {
            $action = https_url(G5_BBS_DIR).'/password_check.php';
            $return_url = G5_HTTP_BBS_URL.'/board.php?bo_table='.$bo_table.'&amp;wr_id='.$wr_id;
        }
        break;
    default :
        alert('w 값이 제대로 넘어오지 않았습니다.');
}

include_once(G5_PATH.'/head.sub.php');

//if ($board['bo_include_head']) { @include ($board['bo_include_head']); }
//if ($board['bo_content_head']) { echo stripslashes($board['bo_content_head']); }

/* 비밀글의 제목을 가져옴 지운아빠 2013-01-29 */
$sql = " select wr_subject from {$write_table}
                      where wr_num = '{$write['wr_num']}'
                      and wr_reply = ''
                      and wr_is_comment = 0 ";
$row = sql_fetch($sql);

$g5['title'] = get_text($row['wr_subject']);

include_once($member_skin_path.'/password.skin.php');

//if ($board['bo_content_tail']) { echo stripslashes($board['bo_content_tail']); }
//if ($board['bo_include_tail']) { @include ($board['bo_include_tail']); }

include_once(G5_PATH.'/tail.sub.php');
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,8 +43,8 @@
 
 include_once(G5_PATH.'/head.sub.php');
 
-//if ($board['bo_include_head']) { @include ($board['bo_include_head']); }
-//if ($board['bo_content_head']) { echo stripslashes($board['bo_content_head']); }
+//if ($board['bo_include_head'] && is_include_path_check($board['bo_content_head'])) { @include ($board['bo_include_head']); }
+//if ($board['bo_content_head']) { echo html_purifier(stripslashes($board['bo_content_head'])); }
 
 /* 비밀글의 제목을 가져옴 지운아빠 2013-01-29 */
 $sql = " select wr_subject from {$write_table}
@@ -57,8 +57,8 @@
 
 include_once($member_skin_path.'/password.skin.php');
 
-//if ($board['bo_content_tail']) { echo stripslashes($board['bo_content_tail']); }
-//if ($board['bo_include_tail']) { @include ($board['bo_include_tail']); }
+//if ($board['bo_content_tail']) { echo html_purifier(stripslashes($board['bo_content_tail'])); }
+//if ($board['bo_include_tail'] && is_include_path_check($board['bo_content_tail'])) { @include ($board['bo_include_tail']); }
 
 include_once(G5_PATH.'/tail.sub.php');
 ?>
```
