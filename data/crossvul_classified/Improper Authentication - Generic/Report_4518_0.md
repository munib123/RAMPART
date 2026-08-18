# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4518_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4518_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 342-382 of the vulnerable file.

            $this->cart = new Cart($idCart);
        } else {
            $idCarrier = (int) $this->cart->id_carrier;
            $this->cart->id_carrier = 0;
            $this->cart->setDeliveryOption(null);
            $this->cart->updateAddressId($this->cart->id_address_delivery, (int) Address::getFirstCustomerAddressId((int) ($customer->id)));
            $this->cart->id_address_delivery = (int) Address::getFirstCustomerAddressId((int) ($customer->id));
            $this->cart->id_address_invoice = (int) Address::getFirstCustomerAddressId((int) ($customer->id));
        }
        $this->cart->id_customer = (int) $customer->id;

        if (isset($idCarrier) && $idCarrier) {
            $deliveryOption = [$this->cart->id_address_delivery => $idCarrier . ','];
            $this->cart->setDeliveryOption($deliveryOption);
        }

        $this->cart->save();
        $this->cookie->id_cart = (int) $this->cart->id;
        $this->cookie->write();
        $this->cart->autosetProductAddress();
    }

    /**
     * Returns a translator depending on service container availability and if the method
     * is called by the installer or not.
     *
     * @param bool $isInstaller Set to true if the method is called by the installer
     *
     * @return Translator
     */
    public function getTranslator($isInstaller = false)
    {
        if (null !== $this->translator) {
            return $this->translator;
        }

        $sfContainer = SymfonyContainer::getInstance();

        if ($isInstaller || null === $sfContainer) {
            // symfony's container isn't available in front office, so we load and configure the translator component
            $this->translator = $this->getTranslatorFromLocale($this->language->locale);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -359,6 +359,8 @@
         $this->cookie->id_cart = (int) $this->cart->id;
         $this->cookie->write();
         $this->cart->autosetProductAddress();
+
+        $this->cookie->registerSession(new CustomerSession());
     }
 
     /**
```
