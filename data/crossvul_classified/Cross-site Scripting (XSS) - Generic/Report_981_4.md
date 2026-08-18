# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 981_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `981_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 9-49 of the vulnerable file.

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
 * these Appropriate Legal Notices must retain the display of the "EspoCRM" word.
 ************************************************************************/

Espo.define('views/preferences/fields/dashboard-tab-list', 'views/fields/array', function (Dep) {

    return Dep.extend({

        setup: function () {
            Dep.prototype.setup.call(this);

            this.translatedOptions = {};
            var list = this.model.get(this.name) || [];
            list.forEach(function (value) {
                this.translatedOptions[value] = value;
            }, this);
        },

        getItemHtml: function (value) {
            var translatedValue = this.translatedOptions[value] || value;

            var html = '' +
            '<div class="list-group-item link-with-role form-inline" data-value="' + value + '">' +
                '<div class="pull-left" style="width: 92%; display: inline-block;">' +
                    '<input data-name="translatedValue" data-value="' + value + '" class="role form-control input-sm" value="'+translatedValue+'">' +
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
  * these Appropriate Legal Notices must retain the display of the "EspoCRM" word.
  ************************************************************************/
 
-Espo.define('views/preferences/fields/dashboard-tab-list', 'views/fields/array', function (Dep) {
+define('views/preferences/fields/dashboard-tab-list', 'views/fields/array', function (Dep) {
 
     return Dep.extend({
 
@@ -39,17 +39,18 @@
                 this.translatedOptions[value] = value;
             }, this);
         },
-
         getItemHtml: function (value) {
-            var translatedValue = this.translatedOptions[value] || value;
+            value = value.toString();
+            var valueSanitized = this.escapeValue(value);
+            var translatedValue = this.escapeValue(this.translatedOptions[value] || value);
 
             var html = '' +
-            '<div class="list-group-item link-with-role form-inline" data-value="' + value + '">' +
+            '<div class="list-group-item link-with-role form-inline" data-value="' + valueSanitized + '">' +
                 '<div class="pull-left" style="width: 92%; display: inline-block;">' +
-                    '<input data-name="translatedValue" data-value="' + value + '" class="role form-control input-sm" value="'+translatedValue+'">' +
+                    '<input data-name="translatedValue" data-value="' + valueSanitized + '" class="role form-control input-sm" value="'+translatedValue+'">' +
                 '</div>' +
                 '<div style="width: 8%; display: inline-block; vertical-align: top;">' +
-                    '<a href="javascript:" class="pull-right" data-value="' + value + '" data-action="removeValue"><span class="fas fa-times"></a>' +
+                    '<a href="javascript:" class="pull-right" data-value="' + valueSanitized + '" data-action="removeValue"><span class="fas fa-times"></a>' +
                 '</div><br style="clear: both;" />' +
             '</div>';
 
@@ -60,7 +61,8 @@
             var data = Dep.prototype.fetch.call(this);
             data.translatedOptions = {};
             (data[this.name] || []).forEach(function (value) {
-                data.translatedOptions[value] = this.$el.find('input[data-name="translatedValue"][data-value="'+value+'"]').val() || value;
+                var valueInternal = value.replace(/"/g, '\\"');
+                data.translatedOptions[value] = this.$el.find('input[data-name="translatedValue"][data-value="'+valueInternal+'"]').val() || value;
             }, this);
 
             return data;
```
