# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 2097_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2097_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 10-37 of the vulnerable file.

copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
-->

<!--
  read icon size from a cookie and set it up
-->
<?jelly escape-by-default='true'?>
<j:jelly xmlns:j="jelly:core" xmlns:x="jelly:xml" xmlns:st="jelly:stapler" xmlns:d="jelly:define" xmlns:l="/lib/layout" xmlns:t="/lib/hudson" xmlns:f="/lib/form">
  <j:set scope="parent" var="iconSize" value="${h.getCookie(request,'iconSize','32x32')}" />
  <!--
    balls look smaller than their actual size,
    so we try not to make the secondary icons look bigger than the icon.
    we want the user's eyes to go to balls, not the clock.
  -->
  <j:set scope="parent" var="subIconSize" value="${iconSize=='32x32'?'24x24':iconSize}"/>
</j:jelly>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 -->
 <?jelly escape-by-default='true'?>
 <j:jelly xmlns:j="jelly:core" xmlns:x="jelly:xml" xmlns:st="jelly:stapler" xmlns:d="jelly:define" xmlns:l="/lib/layout" xmlns:t="/lib/hudson" xmlns:f="/lib/form">
-  <j:set scope="parent" var="iconSize" value="${h.getCookie(request,'iconSize','32x32')}" />
+  <j:set scope="parent" var="iconSize" value="${h.validateIconSize(h.getCookie(request,'iconSize','32x32'))}" />
   <!--
     balls look smaller than their actual size,
     so we try not to make the secondary icons look bigger than the icon.
```
