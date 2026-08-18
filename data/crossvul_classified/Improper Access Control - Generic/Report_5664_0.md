# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 5664_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5664_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.

 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * This resource returns the raw contents of Item_Model data files.  It's analogous to the
 * file_proxy controller, but it uses the REST authentication model.
 */
class data_rest_Core {
  static function get($request) {
    $item = rest::resolve($request->url);
    access::required("view", $item);

    $p = $request->params;
    if (!isset($p->size) || !in_array($p->size, array("thumb", "resize", "full"))) {
      throw new Rest_Exception("Bad Request", 400, array("errors" => array("size" => "invalid")));
    }

    // Note: this code is roughly duplicated in file_proxy, so if you modify this, please look to
    // see if you should make the same change there as well.

    if ($p->size == "full") {
      $file = $item->file_path();
    } else if ($p->size == "resize") {
      $file = $item->resize_path();
    } else {
      $file = $item->thumb_path();
    }

    if (!file_exists($file)) {
      throw new Kohana_404_Exception();
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,6 @@
 class data_rest_Core {
   static function get($request) {
     $item = rest::resolve($request->url);
-    access::required("view", $item);
 
     $p = $request->params;
     if (!isset($p->size) || !in_array($p->size, array("thumb", "resize", "full"))) {
@@ -36,10 +35,16 @@
     // see if you should make the same change there as well.
 
     if ($p->size == "full") {
+      if ($item->is_album()) {
+        throw new Kohana_404_Exception();
+      }
+      access::required("view_full", $item);
       $file = $item->file_path();
     } else if ($p->size == "resize") {
+      access::required("view", $item);
       $file = $item->resize_path();
     } else {
+      access::required("view", $item);
       $file = $item->thumb_path();
     }
 
```
