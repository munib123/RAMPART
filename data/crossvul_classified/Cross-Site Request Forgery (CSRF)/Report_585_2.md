# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 585_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `585_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 12-52 of the vulnerable file.

use yii\base\Module;
use yii\helpers\Url;
use yii\web\Controller;
use yii\widgets\Menu;
use yiiunit\framework\filters\stubs\UserIdentity;
use yiiunit\TestCase;

/**
 * UrlTest.
 * @group helpers
 */
class UrlTest extends TestCase
{
    protected function setUp()
    {
        parent::setUp();
        $this->mockApplication([
            'components' => [
                'request' => [
                    'class' => 'yii\web\Request',
                    'scriptUrl' => '/base/index.php',
                    'hostInfo' => 'http://example.com/',
                    'url' => '/base/index.php&r=site%2Fcurrent&id=42',
                ],
                'urlManager' => [
                    'class' => 'yii\web\UrlManager',
                    'baseUrl' => '/base',
                    'scriptUrl' => '/base/index.php',
                    'hostInfo' => 'http://example.com/',
                ],
                'user' => [
                    'identityClass' => UserIdentity::className(),
                ],
            ],
        ], '\yii\web\Application');
    }

    protected function tearDown()
    {
        Yii::$app->getSession()->removeAll();
        parent::tearDown();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
             'components' => [
                 'request' => [
                     'class' => 'yii\web\Request',
+                    'cookieValidationKey' => '123',
                     'scriptUrl' => '/base/index.php',
                     'hostInfo' => 'http://example.com/',
                     'url' => '/base/index.php&r=site%2Fcurrent&id=42',
```
