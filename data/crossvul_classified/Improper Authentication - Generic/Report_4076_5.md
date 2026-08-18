# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4076_5
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4076_5`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 475-515 of the vulnerable file.

                        $this->copyFromPost($carrier, $this->table);
                        $carrier->position = Carrier::getHigherPosition() + 1;
                        if ($carrier->add()) {
                            if (($_POST['id_' . $this->table] = $carrier->id /* voluntary */) && $this->postImage($carrier->id) && $this->_redirect) {
                                $carrier->setTaxRulesGroup((int) Tools::getValue('id_tax_rules_group'), true);
                                $this->changeZones($carrier->id);
                                $this->changeGroups($carrier->id);
                                $this->updateAssoShop($carrier->id);
                                Tools::redirectAdmin(self::$currentIndex . '&id_' . $this->table . '=' . $carrier->id . '&conf=3&token=' . $this->token);
                            }
                        } else {
                            $this->errors[] = $this->trans('An error occurred while creating an object.', array(), 'Admin.Notifications.Error') . ' <b>' . $this->table . '</b>';
                        }
                    } else {
                        $this->errors[] = $this->trans('You do not have permission to add this.', array(), 'Admin.Notifications.Error');
                    }
                }
            }
            parent::postProcess();
        } elseif (isset($_GET['isFree' . $this->table])) {
            $this->processIsFree();
        } else {
            // if deletion : removes the carrier from the warehouse/carrier association
            if (Tools::isSubmit('delete' . $this->table)) {
                $id = (int) Tools::getValue('id_' . $this->table);
                // Delete from the reference_id and not from the carrier id
                $carrier = new Carrier((int) $id);
                Warehouse::removeCarrier($carrier->id_reference);
            } elseif (Tools::isSubmit($this->table . 'Box') && count(Tools::isSubmit($this->table . 'Box')) > 0) {
                $ids = Tools::getValue($this->table . 'Box');
                array_walk($ids, 'intval');
                foreach ($ids as $id) {
                    // Delete from the reference_id and not from the carrier id
                    $carrier = new Carrier((int) $id);
                    Warehouse::removeCarrier($carrier->id_reference);
                }
            }
            parent::postProcess();
            Carrier::cleanPositions();
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -492,6 +492,11 @@
             }
             parent::postProcess();
         } elseif (isset($_GET['isFree' . $this->table])) {
+            if (!$this->access('edit')) {
+                $this->errors[] = $this->trans('You do not have permission to edit this.', [], 'Admin.Notifications.Error');
+                return;
+            }
+
             $this->processIsFree();
         } else {
             // if deletion : removes the carrier from the warehouse/carrier association
```
