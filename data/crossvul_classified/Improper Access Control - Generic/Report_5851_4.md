# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in xml
**Pair ID:** 5851_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5851_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```xml
Lines 21-45 of the vulnerable file.

OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
-->

<!--
  Present the pseudo "upstream project trigger". Used inside <p:config-trigger>

  "it" is assumed to be a Project object.
-->
<?jelly escape-by-default='true'?>
<j:jelly xmlns:j="jelly:core" xmlns:st="jelly:stapler" xmlns:d="jelly:define" xmlns:l="/lib/layout" xmlns:t="/lib/hudson" xmlns:f="/lib/form">
  <!-- pseudo-trigger to list upstream projects. -->
  <j:set var="up" value="${it.buildTriggerUpstreamProjects}" />
  <f:optionalBlock name="pseudoUpstreamTrigger"
                   help="/help/project-config/upstream.html"
                   title="${%Build after other projects are built}" 
                   checked="${!empty(up)}">
    <f:entry title="${%Project names}"
             description="${%Multiple projects can be specified like 'abc, def'}">
      <f:textbox name="upstreamProjects" value="${h.getProjectListString(up)}"
        checkUrl="'descriptorByName/hudson.tasks.BuildTrigger/check?value='+encodeURIComponent(this.value)"
        autoCompleteField="upstreamProjects"/>
    </f:entry>
  </f:optionalBlock>
</j:jelly>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,7 +38,7 @@
     <f:entry title="${%Project names}"
              description="${%Multiple projects can be specified like 'abc, def'}">
       <f:textbox name="upstreamProjects" value="${h.getProjectListString(up)}"
-        checkUrl="'descriptorByName/hudson.tasks.BuildTrigger/check?value='+encodeURIComponent(this.value)"
+        checkUrl="'descriptorByName/hudson.tasks.BuildTrigger/check?upstream=true&amp;value='+encodeURIComponent(this.value)"
         autoCompleteField="upstreamProjects"/>
     </f:entry>
   </f:optionalBlock>
```
