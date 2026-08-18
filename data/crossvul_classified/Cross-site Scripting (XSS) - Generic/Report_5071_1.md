# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5071_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5071_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 135-182 of the vulnerable file.



    if ($kind==="admin"){
        $conf_templates=$box_conf["templates_admin"];
    }else{
        $conf_templates=$box_conf["templates"];
    }

    //"standard";//標準テンプレートを使用する
    //"custom";//カスタムテンプレートを使用する
    //"theme";//テーマテンプレートを使用する
    if  ($conf_templates==="theme"){

        $tmplfld=$_CONF['path_layout'] .$box_conf['themespath'].$kind;
        if ($kind<>"admin"){

            $tmplfld.="/".$template;
        }
        if (is_dir($tmplfld)) {

        } else if ( SEC_hasRights($adminrights)) {

            $tmplfld=$_CONF['path'] .'plugins/'.$pi_name.'/templates/'.$kind;
            if ($kind<>"admin"){
                $tmplfld.="/default";
            }

        } else {
            COM_handle404();
            exit;
        }
    }else if  ($conf_templates==="custom"){

        $tmplfld=$_CONF['path'] .'plugins/'.$pi_name.'/custom/templates/'.$kind;

        if ($kind<>"admin"){

            $tmplfld.="/".$template;

        }

        if (is_dir($tmplfld)){

        } else if ( SEC_hasRights($adminrights)) {
            $tmplfld=$_CONF['path'] .'plugins/'.$pi_name.'/templates/'.$kind;
            if ($kind<>"admin"){

                $tmplfld.="/default";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,14 +152,7 @@
         }
         if (is_dir($tmplfld)) {
 
-        } else if ( SEC_hasRights($adminrights)) {
-
-            $tmplfld=$_CONF['path'] .'plugins/'.$pi_name.'/templates/'.$kind;
-            if ($kind<>"admin"){
-                $tmplfld.="/default";
-            }
-
-        } else {
+        }else{
             COM_handle404();
             exit;
         }
@@ -174,14 +167,6 @@
         }
 
         if (is_dir($tmplfld)){
-
-        } else if ( SEC_hasRights($adminrights)) {
-            $tmplfld=$_CONF['path'] .'plugins/'.$pi_name.'/templates/'.$kind;
-            if ($kind<>"admin"){
-
-                $tmplfld.="/default";
-
-            }
 
         }else{
             COM_handle404();
@@ -4792,7 +4777,7 @@
         $tpl->set_var('site_admin_url', $_CONF['site_admin_url']);
         $tpl->set_var('layout_url', $_CONF['layout_url']);
         
-        $tpl->set_var ('currenturl', $currenturl);
+        $tpl->set_var ('currenturl', htmlspecialchars($currenturl, ENT_QUOTES, 'UTF-8'));
         
         $tpl->set_var ('site_name', $_CONF['site_name']);
         $tpl->set_var ('site_mail', $_CONF['site_mail']);
```
