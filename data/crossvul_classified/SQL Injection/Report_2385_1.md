# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2385_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2385_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 65-85 of the vulnerable file.

        //$criteria->condition = 'collumnName1 = :id';
        $criteria->order = 'id DESC';
        //$criteria->params = array(':id' => $id);

        $itemCount = Logging::model()->count($criteria);

        $pagination = new CPagination($itemCount);
        $pagination->setPageSize($pageSize);
        $pagination->applyLimit($criteria);  // the trick is here!

        $logEntries = Logging::model()->findAll($criteria);

        $this->render('index', array(
            'entries' => $logEntries, // must be the same as $item_count
            'itemCount' => $itemCount,
            'pageSize' => $pageSize,
            'pagination' => $pagination,
        ));
    }

}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,4 +82,11 @@
         ));
     }
 
+    public function actionFlush()
+    {
+        $this->forcePostRequest();
+        Logging::model()->deleteAll();
+        $this->redirect($this->createUrl('index'));
+    }
+
 }
```
