# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5071_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5071_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 110-150 of the vulnerable file.

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
                            $rt= databox_newlist(
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
                    case 'data':
                        $w= databox_data(
                            $p['id']
                            ,$p['templatedir']
                            ,$p['nohitmsg']
                            ,""
                            ,$p['code']
                            );
                        $rt=$w['display'];
                        break;
                    case 'category':
                        $rt= databox_category(
                            "autotag"
                            ,$p['category_id']
                            ,$p['templatedir']
                            ,$p['nohitmsg']
                            ,$p['perpage']
                            ,$p['page']
                            ,$p['order']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,6 +127,7 @@
                             ,$p['limitcnt']
                             ,$p['newmarkday']
                             ,$p['templatedir']
+                            ,$p['permission']
                             );
                         break;
                     case 'data':
@@ -2015,7 +2016,7 @@
             $templates->set_var ('site_mail', $_CONF['site_mail']);
         
             $currenturl= COM_getCurrentURL();
-            $templates->set_var ('currenturl', $currenturl);
+            $templates->set_var ('currenturl', htmlspecialchars($currenturl, ENT_QUOTES, 'UTF-8'));
             //facebook
             $facebook_consumer_key = trim($_CONF['facebook_consumer_key']);
             $templates->set_var ('facebook_consumer_key', $facebook_consumer_key);
@@ -2486,7 +2487,7 @@
     ,$limitcnt=""
     ,$newmarkday=""
     ,$thtml=null
-)
+    ,$permission=null)
 {
 
     $pi_name="databox";
@@ -2591,6 +2592,13 @@
     $sql.=" , t1.code".LB;
     $sql.=" , t1.description".LB;
 
+    $sql.=" ,t1.owner_id".LB;
+    $sql.=" ,t1.group_id".LB;
+    $sql.=" ,t1.perm_owner".LB;
+    $sql.=" ,t1.perm_group".LB;
+    $sql.=" ,t1.perm_members".LB;
+    $sql.=" ,t1.perm_anon".LB;
+
     $sql .= " FROM ".LB;
     $sql .= " {$tbl1} AS t1 ".LB;
 
@@ -2613,7 +2621,10 @@
        $sql .= " AND t1.draft_flag=0".LB;
     //}
     //アクセス権のないデータ はのぞく
-    $sql .= COM_getPermSql('AND').LB;
+    if  ($_DATABOX_CONF['disable_permission_ignore']=="0" AND strtoupper($permission)=="IGNORE"){
+    }else{
+        $sql .= COM_getPermSql('AND').LB;
+    }
     //公開日以前のデータはのぞく
     $sql .= " AND (released <= NOW())".LB;
 
@@ -2666,7 +2677,18 @@
         $list->set_var ('url', $rt['url']);
         $list->set_var ('title', $title);
 
-        $list->set_var ('description', $description);
+		$list->set_var ('description', $description);
+
+        $permission=SEC_hasAccess2($A);
+        $list->set_var ('permission',$permission);
+        if  ($permission>=2){
+            $list->set_var ('class_a', 'class="gl-tooltip"');
+            $list->set_var ('class_c', 'class="classic"');
+        }else{
+            $list->set_var ('class_a', 'class="databox_nolink"');
+            $list->set_var ('class_c', 'class="databox_displaynon"');
+        }
+
 
         $n=($i%2)+1;
         $class='class="row'.$n.'"';
@@ -3070,7 +3092,9 @@
         }
     }
           
-          
+    if (! defined('THIS_SCRIPT')) {
+        define ('THIS_SCRIPT', 'databox/search.php');
+    }
           
     //-----テーブル
     $tbl1=$_TABLES['DATABOX_category'] ;
```
