# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5071_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5071_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 4760-4800 of the vulnerable file.

    }else{
        $og_image =$box_conf["default_img_url"];
        if ($og_image===""){
            $og_image=$site_logo;
        }
    }
    
    //テンプレートフォルダの設定
    $tmplfld=DATABOX_templatePath($kind,$template,$pi_name);
    if (file_exists ($tmplfld."/headercode.thtml")) {
        $tpl = new Template($tmplfld);
        $tpl->set_file (array (
            'tpl' => 'headercode.thtml',
            ));
    
        $tpl->set_var('xhtml', XHTML);
        $tpl->set_var('site_url', $_CONF['site_url']);
        $tpl->set_var('site_admin_url', $_CONF['site_admin_url']);
        $tpl->set_var('layout_url', $_CONF['layout_url']);
        
        $tpl->set_var ('currenturl', $currenturl);
        
        $tpl->set_var ('site_name', $_CONF['site_name']);
        $tpl->set_var ('site_mail', $_CONF['site_mail']);
        
        $tpl->set_var ('og_title', $og_title);
        $tpl->set_var ('og_image', $og_image);
        $tpl->set_var ('og_description', $og_description);
        $tpl->set_var ('og_type', $og_type);
        $tpl->set_var ('fieldset_name', $fieldset_name);
        
        //facebook
        $facebook_consumer_key = trim($_CONF['facebook_consumer_key']);
        $tpl->set_var ('facebook_consumer_key', $facebook_consumer_key);
        
        if ($kind==="data"){
            DATABOX_getaddtionfieldsDisp($additionfields,$addition_def,$tpl,$chk_user,$pi_name,$fieldset_id);
        }
    
        $tpl->parse ('output', 'tpl');
        $retval .= $tpl->finish ($tpl->get_var ('output'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4777,7 +4777,7 @@
         $tpl->set_var('site_admin_url', $_CONF['site_admin_url']);
         $tpl->set_var('layout_url', $_CONF['layout_url']);
         
-        $tpl->set_var ('currenturl', $currenturl);
+        $tpl->set_var ('currenturl', htmlspecialchars($currenturl, ENT_QUOTES, 'UTF-8'));
         
         $tpl->set_var ('site_name', $_CONF['site_name']);
         $tpl->set_var ('site_mail', $_CONF['site_mail']);
```
