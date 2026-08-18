# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 586_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `586_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-40 of the vulnerable file.

<?php
/* @var $this \yii\web\View */
/* @var $exception \Exception */
/* @var $handler \yii\web\ErrorHandler */
?>
<?php if (method_exists($this, 'beginPage')): ?>
    <?php $this->beginPage() ?>
<?php endif ?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8"/>

    <title><?php
        $name = $handler->getExceptionName($exception);
        if ($exception instanceof \yii\web\HttpException) {
            echo (int) $exception->statusCode . ' ' . $handler->htmlEncode($name);
        } else {
            $name = $handler->getExceptionName($exception);
            if ($name !== null) {
                echo $handler->htmlEncode($name . ' – ' . get_class($exception));
            } else {
                echo $handler->htmlEncode(get_class($exception));
            }
        }
    ?></title>

    <style type="text/css">
/* reset */
html,body,div,span,h1,h2,h3,h4,h5,h6,p,pre,a,code,em,img,strong,b,i,ul,li{
    margin: 0;
    padding: 0;
    border: 0;
    font-size: 100%;
    font: inherit;
    vertical-align: baseline;
}
body{
    line-height: 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,6 @@
         if ($exception instanceof \yii\web\HttpException) {
             echo (int) $exception->statusCode . ' ' . $handler->htmlEncode($name);
         } else {
-            $name = $handler->getExceptionName($exception);
             if ($name !== null) {
                 echo $handler->htmlEncode($name . ' – ' . get_class($exception));
             } else {
```
