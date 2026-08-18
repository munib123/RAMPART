# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 4183_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4183_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 216-256 of the vulnerable file.

            $model->save();
            // clear translation cache because attribute labels are stored in translation
            Mage::app()->cleanCache(array(Mage_Core_Model_Translate::CACHE_TAG));
            return true;
        } catch (Exception $e) {
            $this->_fault('unable_to_save', $e->getMessage());
        }
    }

    /**
     * Remove attribute
     *
     * @param integer|string $attribute attribute ID or code
     * @return boolean
     */
    public function remove($attribute)
    {
        $model = $this->_getAttribute($attribute);

        if ($model->getEntityTypeId() != $this->_entityTypeId) {
            $this->_fault('can_not_delete');
        }

        try {
            $model->delete();
            return true;
        } catch (Exception $e) {
            $this->_fault('can_not_delete', $e->getMessage());
        }
    }

    /**
     * Get full information about attribute with list of options
     *
     * @param integer|string $attribute attribute ID or code
     * @return array
     */
    public function info($attribute)
    {
        $model = $this->_getAttribute($attribute);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -233,6 +233,10 @@
         $model = $this->_getAttribute($attribute);
 
         if ($model->getEntityTypeId() != $this->_entityTypeId) {
+            $this->_fault('can_not_delete');
+        }
+
+        if (!$model->getIsUserDefined()) {
             $this->_fault('can_not_delete');
         }
 
```
