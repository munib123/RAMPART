# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5705_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5705_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php
//simpilotgroup addon module for phpVMS virtual airline system
//
//simpilotgroup addon modules are licenced under the following license:
//Creative Commons Attribution Non-commercial Share Alike (by-nc-sa)
//To view full icense text visit http://creativecommons.org/licenses/by-nc-sa/3.0/
//
//@author David Clark (simpilot)
//@copyright Copyright (c) 2009-2012, David Clark
//@license http://creativecommons.org/licenses/by-nc-sa/3.0/

class PopUpNews extends CodonModule
{
    public function popupnewsitem($id) {

                $result = PopUpNewsData::popupnewsitem($id);
                Template::Set('item', $result);
                Template::Show('popupnews/popupnews_item.tpl');
        }
    

    public function PopUpNewsList($howmany = 5)
    {
        $res = PopUpNewsData::get_news_list($howmany);

        if(!$res)
            return;

        foreach($res as $row)
        {
            Template::Set('id', $row->id);
            Template::Set('subject', $row->subject);
            Template::Set('postdate', date('m/d/Y', $row->postdate));
            Template::Show('popupnews/popupnews_list.tpl');
        }
        echo '<center><a href="http://www.simpilotgroup.com">PopUpNews &copy simpilotgroup.com</a></center>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,8 @@
 {
     public function popupnewsitem($id) {
 
+                if(!is_numeric($id)){header('Location: '.url('/'));}
+        
                 $result = PopUpNewsData::popupnewsitem($id);
                 Template::Set('item', $result);
                 Template::Show('popupnews/popupnews_item.tpl');
@@ -21,6 +23,8 @@
 
     public function PopUpNewsList($howmany = 5)
     {
+        if(!is_numeric($id)){exit;}
+        
         $res = PopUpNewsData::get_news_list($howmany);
 
         if(!$res)
```
