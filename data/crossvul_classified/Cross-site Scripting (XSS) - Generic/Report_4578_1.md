# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4578_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4578_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 12-52 of the vulnerable file.

* obtain it through the world-wide-web, please send an email
* to license@prestashop.com so we can send you a copy immediately.
*
* DISCLAIMER
*
* Do not edit or add to this file if you wish to upgrade PrestaShop to newer
* versions in the future. If you wish to customize PrestaShop for your
* needs please refer to http://www.prestashop.com for more information.
*
*  @author PrestaShop SA <contact@prestashop.com>
*  @copyright  2007-2016 PrestaShop SA
*  @license    http://opensource.org/licenses/afl-3.0.php  Academic Free License (AFL 3.0)
*  International Registered Trademark & Property of PrestaShop SA
*/

if (!defined('_CAN_LOAD_FILES_')) {
    exit;
}

use PrestaShop\PrestaShop\Core\Module\WidgetInterface;

class Ps_Socialfollow extends Module implements WidgetInterface
{
    private $templateFile;

    public function __construct()
    {
        $this->name = 'ps_socialfollow';
        $this->author = 'PrestaShop';
        $this->version = '2.0.0';

        $this->bootstrap = true;
        parent::__construct();

        $this->displayName = $this->trans('Social media follow links', array(), 'Modules.Socialfollow.Admin');
        $this->description = $this->trans('Allows you to add information about your brand\'s social networking accounts.', array(), 'Modules.Socialfollow.Admin');

        $this->ps_versions_compliancy = array('min' => '1.7.1.0', 'max' => _PS_VERSION_);

        $this->templateFile = 'module:ps_socialfollow/ps_socialfollow.tpl';
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,16 +29,29 @@
 }
 
 use PrestaShop\PrestaShop\Core\Module\WidgetInterface;
+use Symfony\Component\Validator\Constraints\Url;
+use Symfony\Component\Validator\Validation;
 
 class Ps_Socialfollow extends Module implements WidgetInterface
 {
     private $templateFile;
 
+    const SOCIAL_NETWORKS = [
+        'facebook',
+        'twitter',
+        'rss',
+        'youtube',
+        'pinterest',
+        'vimeo',
+        'instagram',
+        'linkedin',
+    ];
+
     public function __construct()
     {
         $this->name = 'ps_socialfollow';
         $this->author = 'PrestaShop';
-        $this->version = '2.0.0';
+        $this->version = '2.1.0';
 
         $this->bootstrap = true;
         parent::__construct();
@@ -81,15 +94,7 @@
     public function getContent()
     {
         if (Tools::isSubmit('submitModule')) {
-            Configuration::updateValue('BLOCKSOCIAL_FACEBOOK', Tools::getValue('blocksocial_facebook', ''));
-            Configuration::updateValue('BLOCKSOCIAL_TWITTER', Tools::getValue('blocksocial_twitter', ''));
-            Configuration::updateValue('BLOCKSOCIAL_RSS', Tools::getValue('blocksocial_rss', ''));
-            Configuration::updateValue('BLOCKSOCIAL_YOUTUBE', Tools::getValue('blocksocial_youtube', ''));
-            Configuration::updateValue('BLOCKSOCIAL_PINTEREST', Tools::getValue('blocksocial_pinterest', ''));
-            Configuration::updateValue('BLOCKSOCIAL_VIMEO', Tools::getValue('blocksocial_vimeo', ''));
-            Configuration::updateValue('BLOCKSOCIAL_INSTAGRAM', Tools::getValue('blocksocial_instagram', ''));
-            Configuration::updateValue('BLOCKSOCIAL_LINKEDIN', Tools::getValue('blocksocial_linkedin', ''));
-
+            $this->updateFields();
             $this->_clearCache('*');
 
             Tools::redirectAdmin($this->context->link->getAdminLink('AdminModules').'&configure='.$this->name.'&tab_module='.$this->tab.'&conf=4&module_name='.$this->name);
@@ -180,16 +185,11 @@
 
     public function getConfigFieldsValues()
     {
-        return array(
-            'blocksocial_facebook' => Tools::getValue('blocksocial_facebook', Configuration::get('BLOCKSOCIAL_FACEBOOK')),
-            'blocksocial_twitter' => Tools::getValue('blocksocial_twitter', Configuration::get('BLOCKSOCIAL_TWITTER')),
-            'blocksocial_rss' => Tools::getValue('blocksocial_rss', Configuration::get('BLOCKSOCIAL_RSS')),
-            'blocksocial_youtube' => Tools::getValue('blocksocial_youtube', Configuration::get('BLOCKSOCIAL_YOUTUBE')),
-            'blocksocial_pinterest' => Tools::getValue('blocksocial_pinterest', Configuration::get('BLOCKSOCIAL_PINTEREST')),
-            'blocksocial_vimeo' => Tools::getValue('blocksocial_vimeo', Configuration::get('BLOCKSOCIAL_VIMEO')),
-            'blocksocial_instagram' => Tools::getValue('blocksocial_instagram', Configuration::get('BLOCKSOCIAL_INSTAGRAM')),
-            'blocksocial_linkedin' => Tools::getValue('blocksocial_linkedin', Configuration::get('BLOCKSOCIAL_LINKEDIN')),
-        );
+        $result = [];
+        foreach (static::SOCIAL_NETWORKS as $social) {
+            $result['blocksocial_' . $social] = Configuration::get('BLOCKSOCIAL_' . strtoupper($social));
+        }
+        return $result;
     }
 
     public function renderWidget($hookName = null, array $configuration = [])
@@ -273,4 +273,23 @@
             'social_links' => $social_links,
         );
     }
+
+    /**
+     * Update form fields.
+     * Check all social networks form value and verify the URL is valid.
+     * Do nothing if a violation is spotted.
+     */
+    protected function updateFields()
+    {
+        $validator = Validation::createValidator();
+        $constraints = [new Url()];
+
+        foreach (static::SOCIAL_NETWORKS as $social) {
+            $value = Tools::getValue('blocksocial_' . $social, '');
+            $violations = $validator->validate($value, $constraints);
+            if (0 === count($violations)) {
+                Configuration::updateValue('BLOCKSOCIAL_' . strtoupper($social), $value);
+            }
+        }
+    }
 }
```
