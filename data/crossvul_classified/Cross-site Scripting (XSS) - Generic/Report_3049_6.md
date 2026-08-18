# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 3049_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3049_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 19-46 of the vulnerable file.

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
  <l:layout title="${it.displayName}">
    <j:invokeStatic var="currentThread" className="java.lang.Thread" method="currentThread" />
    <j:invoke var="buildClass" on="${currentThread.contextClassLoader}" method="loadClass">
      <j:arg value="hudson.model.Run"/>
    </j:invoke>
    <j:set var="build" value="${request.findAncestorObject(buildClass)}" />
		<st:include page="sidepanel.jelly" it="${build}" />
		<l:main-panel>
			<h1>${%Build} ${build.displayName}</h1>
			<l:pane title="${%Parameters}" width="3">
			<j:forEach var="parameterValue" items="${it.parameters}">
				<st:include it="${parameterValue}"
					page="value.jelly" />
			</j:forEach>
			</l:pane>
		</l:main-panel>
  </l:layout>
</j:jelly>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,7 @@
 		<l:main-panel>
 			<h1>${%Build} ${build.displayName}</h1>
 			<l:pane title="${%Parameters}" width="3">
+                        <j:set var="escapeEntryTitleAndDescription" value="true"/> <!-- SECURITY-353 defense unless overridden -->
 			<j:forEach var="parameterValue" items="${it.parameters}">
 				<st:include it="${parameterValue}"
 					page="value.jelly" />
```
