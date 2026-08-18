# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 426_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `426_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.


if ($is_admin != 'super')
    alert('최고관리자만 접근 가능합니다.');

$mb = get_member($cf_admin);
if (!$mb['mb_id'])
    alert('최고관리자 회원아이디가 존재하지 않습니다.');

check_admin_token();

// 본인확인을 사용할 경우 아이핀, 휴대폰인증 중 하나는 선택되어야 함
if($_POST['cf_cert_use'] && !$_POST['cf_cert_ipin'] && !$_POST['cf_cert_hp'])
    alert('본인확인을 위해 아이핀 또는 휴대폰 본인학인 서비스를 하나이상 선택해 주십시오');

if(!$_POST['cf_cert_use']) {
    $_POST['cf_cert_ipin'] = '';
    $_POST['cf_cert_hp'] = '';
}

$cf_social_servicelist = !empty($_POST['cf_social_servicelist']) ? implode(',', $_POST['cf_social_servicelist']) : '';

$sql = " update {$g5['config_table']}
            set cf_title = '{$_POST['cf_title']}',
                cf_admin = '{$_POST['cf_admin']}',
                cf_admin_email = '{$_POST['cf_admin_email']}',
                cf_admin_email_name = '{$_POST['cf_admin_email_name']}',
                cf_add_script = '{$_POST['cf_add_script']}',
                cf_use_point = '{$_POST['cf_use_point']}',
                cf_point_term = '{$_POST['cf_point_term']}',
                cf_use_copy_log = '{$_POST['cf_use_copy_log']}',
                cf_use_email_certify = '{$_POST['cf_use_email_certify']}',
                cf_login_point = '{$_POST['cf_login_point']}',
                cf_cut_name = '{$_POST['cf_cut_name']}',
                cf_nick_modify = '{$_POST['cf_nick_modify']}',
                cf_new_skin = '{$_POST['cf_new_skin']}',
                cf_new_rows = '{$_POST['cf_new_rows']}',
                cf_search_skin = '{$_POST['cf_search_skin']}',
                cf_connect_skin = '{$_POST['cf_connect_skin']}',
                cf_faq_skin = '{$_POST['cf_faq_skin']}',
                cf_read_point = '{$_POST['cf_read_point']}',
                cf_write_point = '{$_POST['cf_write_point']}',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,6 +25,8 @@
 }
 
 $cf_social_servicelist = !empty($_POST['cf_social_servicelist']) ? implode(',', $_POST['cf_social_servicelist']) : '';
+
+$_POST['cf_title'] = strip_tags($_POST['cf_title']);
 
 $sql = " update {$g5['config_table']}
             set cf_title = '{$_POST['cf_title']}',
```
