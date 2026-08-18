# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in html
**Pair ID:** 5842_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```html
Lines 30-53 of the vulnerable file.

            </tr>
          </thead>
          <tbody>
            <wicket:container wicket:id="scripts">
              <tr wicket:id="scriptRows">
                <td wicket:id="regionId">[ProjectForge]</td>
                <td wicket:id="version">[3.3.44]</td>
                <td wicket:id="date">[2011-02-27]</td>
                <td wicket:id="preCheckResult">[--]</td>
                <td><span wicket:id="update">[run]</span></td>
                <td wicket:id="description">[...]</td>
              </tr>
            </wicket:container>
          </tbody>
        </table>
      </div>
      <wicket:container wicket:id="flowform">[the form fields]</wicket:container>
      <div class="button_bar">
        <wicket:container wicket:id="buttons">[action buttons]</wicket:container>
      </div>
    </form>
  </wicket:extend>
</body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,6 +47,7 @@
       <div class="button_bar">
         <wicket:container wicket:id="buttons">[action buttons]</wicket:container>
       </div>
+      <input type="hidden" wicket:id="csrfToken" />
     </form>
   </wicket:extend>
 </body>
```
