# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 981_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `981_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 9-48 of the vulnerable file.

 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * EspoCRM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with EspoCRM. If not, see http://www.gnu.org/licenses/.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU General Public License version 3.
 *
 * In accordance with Section 7(b) of the GNU General Public License version 3,
 * these Appropriate Legal Notices must retain the display of tтhe "EspoCRM" word.
 ************************************************************************/

Espo.define('views/attachment/fields/name', 'views/fields/varchar', function (Dep) {

    return Dep.extend({

        detailTemplate: 'attachment/fields/name/detail',

        data: function () {
            var data = Dep.prototype.data.call(this);

            var url = this.getBasePath() + '?entryPoint=download&id=' + this.model.id;
            if (this.getUser().get('portalId')) {
                url += '&portalId=' + this.getUser().get('portalId');
            }

            data.url = url;
            return data;
        }

    });
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
  * these Appropriate Legal Notices must retain the display of tтhe "EspoCRM" word.
  ************************************************************************/
 
-Espo.define('views/attachment/fields/name', 'views/fields/varchar', function (Dep) {
+define('views/attachment/fields/name', 'views/fields/varchar', function (Dep) {
 
     return Dep.extend({
 
```
