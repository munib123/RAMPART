# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in html
**Pair ID:** 5842_9
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_9`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```html
Lines 15-39 of the vulnerable file.

        <thead>
          <tr>
            <th><wicket:message key="fibu.kost1" /></th>
            <th><wicket:message key="fibu.kost2" /></th>
            <th><wicket:message key="fibu.common.netto" /></th>
            <th><wicket:message key="percent" /></th>
            <th>&nbsp;</th>
          </tr>
        </thead>
        <tbody id="costAssignmentBody">
          <tr wicket:id="rows">
            <td><input wicket:id="kost1" title="3.501.00.01 - Kai Reinhard" /></td>
            <td><input wicket:id="kost2" title="5.105.03.07 - ACME Web portal" /></td>
            <td><input wicket:id="netto" /></td>
            <td wicket:id="percentage">[30%]</td>
            <td style="vertical-align: middle;" wicket:id="deleteEntry">[delete button]</td>
          </tr>
        </tbody>
      </table>
      <div>
      <wicket:message key="rest" />: <span wicket:id="restValue">[-1234,00]</span></div>
    </form>
  </wicket:panel>
</body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,10 @@
         </tbody>
       </table>
       <div>
-      <wicket:message key="rest" />: <span wicket:id="restValue">[-1234,00]</span></div>
+        <wicket:message key="rest" />
+        : <span wicket:id="restValue">[-1234,00]</span>
+      </div>
+      <input type="hidden" wicket:id="csrfToken" />
     </form>
   </wicket:panel>
 </body>
```
