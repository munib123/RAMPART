# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2385_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2385_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 26-66 of the vulnerable file.

     */
    public function accessRules()
    {
        return array(
            array('allow', // allow authenticated user to perform 'create' and 'update' actions
                'users' => array('@'),
            ),
            array('deny', // deny all users
                'users' => array('*'),
            ),
        );
    }

    /**
     * Returns a List of all notifications for an user
     */
    public function actionIndex()
    {

        // the id from the last entry loaded
        $lastEntryId = Yii::app()->request->getParam('from');

        // create database query
        $criteria = new CDbCriteria();
        if ($lastEntryId > 0) {
            // start from last entry id loaded
            $criteria->condition = 'id<' . $lastEntryId;
        }
        $criteria->order = 'seen ASC, created_at DESC';
        $criteria->limit = 6;

        // safe query
        $notifications = Notification::model()->findAllByAttributes(array('user_id' => Yii::app()->user->id), $criteria);

        // variable for notification list
        $output = "";

        foreach ($notifications as $notification) {
            // format and save all entries
            $output .= $notification->getOut();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,13 +43,14 @@
     {
 
         // the id from the last entry loaded
-        $lastEntryId = Yii::app()->request->getParam('from');
+        $lastEntryId = (int) Yii::app()->request->getParam('from');
 
         // create database query
         $criteria = new CDbCriteria();
         if ($lastEntryId > 0) {
             // start from last entry id loaded
-            $criteria->condition = 'id<' . $lastEntryId;
+            $criteria->condition = 'id<:lastEntryId';
+            $criteria->params = array(':lastEntryId' => $lastEntryId);
         }
         $criteria->order = 'seen ASC, created_at DESC';
         $criteria->limit = 6;
```
