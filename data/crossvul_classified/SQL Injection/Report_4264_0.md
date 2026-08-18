# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4264_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4264_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php

namespace app\admin\controller;

use app\common\controller\Backend;
use fast\Random;
use think\addons\Service;
use think\Cache;
use think\Config;
use think\Db;
use think\Lang;

/**
 * Ajax异步请求接口
 * @internal
 */
class Ajax extends Backend
{

    protected $noNeedLogin = ['lang'];
    protected $noNeedRight = ['*'];
    protected $layout = '';

    public function _initialize()
    {
        parent::_initialize();

        //设置过滤方法
        $this->request->filter(['strip_tags', 'htmlspecialchars']);
    }

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 use think\Config;
 use think\Db;
 use think\Lang;
+use think\Validate;
 
 /**
  * Ajax异步请求接口
@@ -155,6 +156,9 @@
         $field = $this->request->post("field");
         //操作的数据表
         $table = $this->request->post("table");
+        if (!Validate::is($table, "alphaDash")) {
+            $this->error();
+        }
         //主键
         $pk = $this->request->post("pk");
         //排序的方式
@@ -214,16 +218,19 @@
             case 'content':
                 rmdirs(CACHE_PATH, false);
                 Cache::clear();
-                if ($type == 'content')
+                if ($type == 'content') {
                     break;
+                }
             case 'template':
                 rmdirs(TEMP_PATH, false);
-                if ($type == 'template')
+                if ($type == 'template') {
                     break;
+                }
             case 'addons':
                 Service::refresh();
-                if ($type == 'addons')
+                if ($type == 'addons') {
                     break;
+                }
         }
 
         \think\Hook::listen("wipecache_after");
```
