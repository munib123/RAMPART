# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5706_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5706_0`)

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

                if(!is_numeric($id)){header('Location: '.url('/'));}
        
                $result = PopUpNewsData::popupnewsitem($id);
                Template::Set('item', $result);
                Template::Show('popupnews/popupnews_item.tpl');
        }
    

    public function PopUpNewsList($howmany = 5)
    {
        if(!is_numeric($howmany)){exit;}
        
        $res = PopUpNewsData::get_news_list($howmany);

        if(!$res)
            return;

        foreach($res as $row)
        {
            Template::Set('id', $row->id);
            Template::Set('subject', $row->subject);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,7 @@
 {
     public function popupnewsitem($id) {
 
+                $id = intval($id);
                 if(!is_numeric($id)){header('Location: '.url('/'));}
         
                 $result = PopUpNewsData::popupnewsitem($id);
@@ -23,6 +24,7 @@
 
     public function PopUpNewsList($howmany = 5)
     {
+        $howmany = intval($howmany);
         if(!is_numeric($howmany)){exit;}
         
         $res = PopUpNewsData::get_news_list($howmany);
```
