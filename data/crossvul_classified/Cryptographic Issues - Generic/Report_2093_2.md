# CrossVul Fix Pair: Cryptographic Issues in xml
**Pair ID:** 2093_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2093_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```xml
Lines 13-38 of the vulnerable file.

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

<?jelly escape-by-default='true'?>
<j:jelly xmlns:j="jelly:core" xmlns:st="jelly:stapler" xmlns:d="jelly:define"
	xmlns:l="/lib/layout" xmlns:t="/lib/hudson" xmlns:f="/lib/form"
	xmlns:i="jelly:fmt" xmlns:p="/lib/hudson/project">
    <f:entry title="${%Name}" help="/help/parameter/name.html">
		<f:textbox name="parameter.name" value="${instance.name}" />
	</f:entry>
	<f:entry title="${%Default Value}" help="/help/parameter/string-default.html">
		<f:password name="parameter.defaultValue" value="${instance.defaultValue}" />
	</f:entry>
    <f:entry title="${%Description}" help="/help/parameter/description.html">
        <f:textarea name="parameter.description" value="${instance.description}" />
    </f:entry>
</j:jelly>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,7 @@
 		<f:textbox name="parameter.name" value="${instance.name}" />
 	</f:entry>
 	<f:entry title="${%Default Value}" help="/help/parameter/string-default.html">
-		<f:password name="parameter.defaultValue" value="${instance.defaultValue}" />
+		<f:password name="parameter.defaultValue" value="${instance.defaultValueAsSecret}" />
 	</f:entry>
     <f:entry title="${%Description}" help="/help/parameter/description.html">
         <f:textarea name="parameter.description" value="${instance.description}" />
```
