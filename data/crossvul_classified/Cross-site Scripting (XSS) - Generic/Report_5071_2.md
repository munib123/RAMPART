# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5071_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5071_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 112-152 of the vulnerable file.

                    case 'newlist':
                            if ($p['category_id']<>""){
                                $m="id";
                                $categories=$p['category_id'];
                            }elseif ($p['category_code']<>"") {
                                $m="code";
                                $categories=$p['category_code'];
                            }else{
                                $m="ALL";
                                $categories="";
                            }
                            $rt= userbox_newlist(
                            $m
                            ,$categories
                            ,$p['rss_file']
                            ,$p['title_trim_length']
                            ,$p['intervalday']
                            ,$p['limitcnt']
                            ,$p['newmarkday']
                            ,$p['templatedir']
                            );
                        break;

                    case 'profile':
                        $w= userbox_profile(
                            $p['uid']
                            ,$p['templatedir']
                            ,$p['nohitmsg']
                            ,""
                            ,$p['username']
                            );
                        $rt=$w['display'];
                        break;
                    case 'category':
                        $rt= userbox_category(
                            "autotag"
                            ,$p['category_id']
                            ,$p['templatedir']
                            ,$p['nohitmsg']
                            ,$p['perpage']
                            ,$p['page']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,6 +129,7 @@
                             ,$p['limitcnt']
                             ,$p['newmarkday']
                             ,$p['templatedir']
+                            ,$p['permission']
                             );
                         break;
 
@@ -670,14 +671,39 @@
             $templates->set_var ('data_datefield_shortdate', strftime( $_CONF['shortdate'], $A['datefield_un'] ));
             $templates->set_var ('data_released', $released_ary[0]);
             $templates->set_var ('data_released_shortdate', strftime( $_CONF['shortdate'], $A['released_un'] ));
+            $templates->set_var ('data_released_date', strftime( $_CONF['date'], $A['released_un'] ));
+            $templates->set_var ('data_released_daytime', strftime( $_CONF['daytime'], $A['released_un'] ));
+            $templates->set_var ('data_released_dateonly', strftime( $_CONF['dateonly'], $A['released_un'] ));
+            $templates->set_var ('data_released_timeonly', strftime( $_CONF['timeonly'], $A['released_un'] ));
+            $templates->set_var ('data_released_b', strftime( "%b" , $A['released_un']));
+            $templates->set_var ('data_released_B', strftime( "%B" , $A['released_un']));
+            $templates->set_var ('data_released_d', strftime( "%d" , $A['released_un']));
+            $templates->set_var ('data_released_e', strftime( "%e" , $A['released_un']));
+            
             //公開終了日 Expired to publish
             if ($A['expired'] ==="0000-00-00 00:00:00"){
                 $templates->set_var ('data_expired', "");
                 $templates->set_var ('data_expired_shortdate', "" );
+                $templates->set_var ('data_expired_date', "" );
+                $templates->set_var ('data_expired_daytime', "" );
+                $templates->set_var ('data_expired_dateonly', "" );
+                $templates->set_var ('data_expired_timeonly', "" );
+                $templates->set_var ('data_expired_b', "" );
+                $templates->set_var ('data_expired_B', "" );
+                $templates->set_var ('data_expired_d', "" );
+                $templates->set_var ('data_expired_e', "" );
             }else{
                 $wary = COM_getUserDateTimeFormat($A['expired_un']);
                 $templates->set_var ('data_expired', $expired_ary[0]);
                 $templates->set_var ('data_expired_shortdate', strftime( $_CONF['shortdate'], $A['expired_un'] ));
+                $templates->set_var ('data_expired_date', strftime( $_CONF['date'], $A['expired_un'] ));
+                $templates->set_var ('data_expired_daytime', strftime( $_CONF['daytime'], $A['expired_un'] ));
+                $templates->set_var ('data_expired_dateonly', strftime( $_CONF['dateonly'], $A['expired_un'] ));
+                $templates->set_var ('data_expired_timeonly', strftime( $_CONF['timeonly'], $A['expired_un'] ));
+                $templates->set_var ('data_expired_b', strftime( "%b" , $A['expired_un']));
+                $templates->set_var ('data_expired_B', strftime( "%B" , $A['expired_un']));
+                $templates->set_var ('data_expired_d', strftime( "%d" , $A['expired_un']));
+                $templates->set_var ('data_expired_e', strftime( "%e" , $A['expired_un']));
             }
             $remaingdays="";
             if ($expired<>"0000-00-00 00:00:00") {
@@ -1298,7 +1324,7 @@
             $templates->set_var ('site_mail', $_CONF['site_mail']);
         
             $currenturl= COM_getCurrentURL();
-            $templates->set_var ('currenturl', $currenturl);
+            $templates->set_var ('currenturl', htmlspecialchars($currenturl, ENT_QUOTES, 'UTF-8'));
             //facebook
             $facebook_consumer_key = trim($_CONF['facebook_consumer_key']);
             $templates->set_var ('facebook_consumer_key', $facebook_consumer_key);
@@ -1386,29 +1412,69 @@
             $wary = COM_getUserDateTimeFormat($A['modified_un']);
             $templates->set_var ('modified',$wary[0]);
             $templates->set_var ('modified_shortdate', strftime( $_CONF['shortdate'], $A['modified_un'] ));
+            $templates->set_var ('modified_date', strftime( $_CONF['date'], $A['modified_un'] ));
+            $templates->set_var ('modified_daytime', strftime( $_CONF['daytime'], $A['modified_un'] ));
+            $templates->set_var ('modified_dateonly', strftime( $_CONF['dateonly'], $A['modified_un'] ));
+            $templates->set_var ('modified_timeonly', strftime( $_CONF['timeonly'], $A['modified_un'] ));
+            $templates->set_var ('modified_b', strftime( "%b" , $A['modified_un']));
+            $templates->set_var ('modified_B', strftime( "%B" , $A['modified_un']));
+            $templates->set_var ('modified_d', strftime( "%d" , $A['modified_un']));
+            $templates->set_var ('modified_e', strftime( "%e" , $A['modified_un']));
             //作成日付
             $templates->set_var('lang_created', $LANG_USERBOX_ADMIN['created']);
             $wary = COM_getUserDateTimeFormat($A['created_un']);
             $templates->set_var ('created', $wary[0]);
             $templates->set_var ('created_shortdate', strftime( $_CONF['shortdate'], $A['created_un'] ));
+            $templates->set_var ('created_date', strftime( $_CONF['date'], $A['created_un'] ));
+            $templates->set_var ('created_daytime', strftime( $_CONF['daytime'], $A['created_un'] ));
+            $templates->set_var ('created_dateonly', strftime( $_CONF['dateonly'], $A['created_un'] ));
+            $templates->set_var ('created_timeonly', strftime( $_CONF['timeonly'], $A['created_un'] ));
+            $templates->set_var ('created_b', strftime( "%b" , $A['created_un']));
+            $templates->set_var ('created_B', strftime( "%B" , $A['created_un']));
+            $templates->set_var ('created_d', strftime( "%d" , $A['created_un']));
+            $templates->set_var ('created_e', strftime( "%e" , $A['created_un']));
             //公開日
             $templates->set_var('lang_released', $LANG_USERBOX_ADMIN['released']);
             $wary = COM_getUserDateTimeFormat($A['released_un']);
             $templates->set_var ('released', $wary[0]);
             $templates->set_var ('released_shortdate', strftime( $_CONF['shortdate'], $A['released_un'] ));
-            //公開終了日
+            $templates->set_var ('released_date', strftime( $_CONF['date'], $A['released_un'] ));
+            $templates->set_var ('released_daytime', strftime( $_CONF['daytime'], $A['released_un'] ));
+            $templates->set_var ('released_dateonly', strftime( $_CONF['dateonly'], $A['released_un'] ));
+            $templates->set_var ('released_timeonly', strftime( $_CONF['timeonly'], $A['released_un'] ));
+            $templates->set_var ('released_b', strftime( "%b" , $A['released_un']));
+            $templates->set_var ('released_B', strftime( "%B" , $A['released_un']));
+            $templates->set_var ('released_d', strftime( "%d" , $A['released_un']));
+            $templates->set_var ('released_e', strftime( "%e" , $A['released_un']));
+             //公開終了日
             $templates->set_var('lang_expired', $LANG_USERBOX_ADMIN['expired']);
             if ($A['expired'] ==="0000-00-00 00:00:00"){
                 $templates->set_var ('expired', "");
                 $templates->set_var ('expired_shortdate', "" );
+                $templates->set_var ('expired_date', "" );
+                $templates->set_var ('expired_daytime', "" );
+                $templates->set_var ('expired_dateonly', "" );
+                $templates->set_var ('expired_timeonly', "" );
+                $templates->set_var ('expired_b', "" );
+                $templates->set_var ('expired_B', "" );
+                $templates->set_var ('expired_d', "" );
+                $templates->set_var ('expired_e', "" );
             }else{
                 $wary = COM_getUserDateTimeFormat($A['expired_un']);
                 $templates->set_var ('expired', $wary[0]);
... (diff truncated)
```
