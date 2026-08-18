# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4093_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4093_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 237-258 of the vulnerable file.

         ])
      )->isGreaterThan(0);

      foreach ($dates as $date => $expected) {
         $this->boolean($calendar->isHoliday($date))->isIdenticalTo($expected);
      }
   }

   public function testClone() {
      $calendar = new \Calendar();
      $default_id = getItemByTypeName('Calendar', 'Default', true);
      // get Default calendar
      $this->boolean($calendar->getFromDB($default_id))->isTrue();
      $this->addXmas($calendar);

      $id = $calendar->clone();
      $this->integer($id)->isGreaterThan($default_id);
      $this->boolean($calendar->getFromDB($id))->isTrue();
      //should have been duplicated too.
      $this->checkXmas($calendar);
   }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,5 +254,19 @@
       $this->boolean($calendar->getFromDB($id))->isTrue();
       //should have been duplicated too.
       $this->checkXmas($calendar);
+
+      //change name, and clone again
+      $this->boolean($calendar->update(['id' => $id, 'name' => "Je s\'apelle Groot"]))->isTrue();
+
+      $calendar = new \Calendar();
+      $this->boolean($calendar->getFromDB($id))->isTrue();
+
+      $this->boolean($calendar->duplicate())->isTrue();
+      $other_id = $calendar->fields['id'];
+      $this->integer($other_id)->isGreaterThan($id);
+      $this->boolean($calendar->getFromDB($other_id))->isTrue();
+      //should have been duplicated too.
+      $this->checkXmas($calendar);
+
    }
 }
```
