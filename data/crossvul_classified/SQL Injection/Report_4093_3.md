# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4093_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4093_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

 * (at your option) any later version.
 *
 * GLPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GLPI. If not, see <http://www.gnu.org/licenses/>.
 * ---------------------------------------------------------------------
*/

namespace tests\units;

use DbTestCase;

/* Test for inc/computer.class.php */

class Computer extends DbTestCase {

   private function getNewComputer() {
      $computer = getItemByTypeName('Computer', '_test_pc01');
      $fields   = $computer->fields;
      unset($fields['id']);
      unset($fields['date_creation']);
      unset($fields['date_mod']);
      $fields['name'] = $this->getUniqueString();
      $this->integer((int)$computer->add($fields))->isGreaterThan(0);
      return $computer;
   }

   private function getNewPrinter() {
      $printer  = getItemByTypeName('Printer', '_test_printer_all');
      $pfields  = $printer->fields;
      unset($pfields['id']);
      unset($pfields['date_creation']);
      unset($pfields['date_mod']);
      $pfields['name'] = $this->getUniqueString();
      $this->integer((int)$printer->add($pfields))->isGreaterThan(0);
      return $printer;
   }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,12 @@
 /* Test for inc/computer.class.php */
 
 class Computer extends DbTestCase {
+
+   protected function getUniqueString() {
+      $string = parent::getUniqueString();
+      $string .= "with a ' inside!";
+      return $string;
+   }
 
    private function getNewComputer() {
       $computer = getItemByTypeName('Computer', '_test_pc01');
@@ -45,7 +51,7 @@
       unset($fields['date_creation']);
       unset($fields['date_mod']);
       $fields['name'] = $this->getUniqueString();
-      $this->integer((int)$computer->add($fields))->isGreaterThan(0);
+      $this->integer((int)$computer->add(\Toolbox::addslashes_deep($fields)))->isGreaterThan(0);
       return $computer;
    }
 
@@ -56,7 +62,7 @@
       unset($pfields['date_creation']);
       unset($pfields['date_mod']);
       $pfields['name'] = $this->getUniqueString();
-      $this->integer((int)$printer->add($pfields))->isGreaterThan(0);
+      $this->integer((int)$printer->add(\Toolbox::addslashes_deep($pfields)))->isGreaterThan(0);
       return $printer;
    }
 
@@ -89,7 +95,7 @@
              'states_id'    => $this->getUniqueInteger(),
              'locations_id' => $this->getUniqueInteger(),
       ];
-      $this->boolean($computer->update($in))->isTrue();
+      $this->boolean($computer->update(\Toolbox::addslashes_deep($in)))->isTrue();
       $this->boolean($computer->getFromDB($computer->getID()))->isTrue();
       $this->boolean($printer->getFromDB($printer->getID()))->isTrue();
       unset($in['id']);
@@ -134,7 +140,7 @@
              'states_id'    => $this->getUniqueInteger(),
              'locations_id' => $this->getUniqueInteger(),
       ];
-      $this->boolean($computer->update($in2))->isTrue();
+      $this->boolean($computer->update(\Toolbox::addslashes_deep($in2)))->isTrue();
       $this->boolean($computer->getFromDB($computer->getID()))->isTrue();
       $this->boolean($printer->getFromDB($printer->getID()))->isTrue();
       unset($in2['id']);
@@ -255,7 +261,7 @@
              'states_id'    => $this->getUniqueInteger(),
              'locations_id' => $this->getUniqueInteger(),
       ];
-      $this->boolean($computer->update($in))->isTrue();
+      $this->boolean($computer->update(\Toolbox::addslashes_deep($in)))->isTrue();
       $this->boolean($computer->getFromDB($computer->getID()))->isTrue();
 
       $printer = new \Printer();
@@ -431,6 +437,8 @@
       )->isGreaterThan(0);
 
       //clone!
+      $computer = new \Computer(); //$computer->fields contents is already escaped!
+      $this->boolean($computer->getFromDB($id))->isTrue();
       $added = $computer->clone();
       $this->integer((int)$added)->isGreaterThan(0);
       $this->integer($added)->isNotEqualTo($computer->fields['id']);
```
