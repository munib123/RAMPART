# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4561_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4561_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 992-1032 of the vulnerable file.


                    return $return;
                }
            }
        } catch (PrestaShopException $e) {
            $this->errors[] = $e->getMessage();
        }

        return false;
    }

    /**
     * Object Delete images.
     *
     * @return ObjectModel|false
     */
    public function processDeleteImage()
    {
        if (Validate::isLoadedObject($object = $this->loadObject())) {
            if (($object->deleteImage())) {
                $redirect = self::$currentIndex . '&update' . $this->table . '&' . $this->identifier . '=' . Tools::getValue($this->identifier) . '&conf=7&token=' . $this->token;
                if (!$this->ajax) {
                    $this->redirect_after = $redirect;
                } else {
                    $this->content = 'ok';
                }
            }
        }
        $this->errors[] = $this->trans('An error occurred while attempting to delete the image. (cannot load object).', [], 'Admin.Notifications.Error');

        return $object;
    }

    /**
     * @param string $text_delimiter
     *
     * @throws PrestaShopException
     */
    public function processExport($text_delimiter = '"')
    {
        // clean buffer
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1009,7 +1009,7 @@
     {
         if (Validate::isLoadedObject($object = $this->loadObject())) {
             if (($object->deleteImage())) {
-                $redirect = self::$currentIndex . '&update' . $this->table . '&' . $this->identifier . '=' . Tools::getValue($this->identifier) . '&conf=7&token=' . $this->token;
+                $redirect = self::$currentIndex . '&update' . $this->table . '&' . $this->identifier . '=' . (int) Tools::getValue($this->identifier) . '&conf=7&token=' . $this->token;
                 if (!$this->ajax) {
                     $this->redirect_after = $redirect;
                 } else {
```
