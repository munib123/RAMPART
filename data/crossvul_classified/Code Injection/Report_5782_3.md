# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 5782_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5782_3`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 9-49 of the vulnerable file.

//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

// This is a manifest file that'll be compiled into application.js, which will include all the files
// listed below.
//
// Any JavaScript/Coffee file within this directory, lib/assets/javascripts, vendor/assets/javascripts,
// or vendor/assets/javascripts of plugins, if any, can be referenced here using a relative path.
//
// It's not advisable to add code directly here, but if you do, it'll appear at the bottom of the
// the compiled file.
//
// WARNING: THE FIRST BLANK LINE MARKS THE END OF WHAT'S TO BE PROCESSED, ANY BLANK LINE SHOULD
// GO AFTER THE REQUIRES BELOW.
//
//= require jquery
//= require jquery_ujs
//= require jquery-ui
//
//= require jquery-cookie
//= require jquery-leanModal
//= require jquery-timers
//
//= require flot/flot
//= require flot/resize
//= require flot/stack
//= require flot/time
//
//= require sh/manifest
//
//= require bootstrap
//
//= require squash_javascript
//= require configure_squash_client
//
//= require accordion
//= require autocomplete
//= require bug_file_formatter
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,6 @@
 //
 //= require jquery
 //= require jquery_ujs
-//= require jquery-ui
 //
 //= require jquery-cookie
 //= require jquery-leanModal
```
