# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in html
**Pair ID:** 3168_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3168_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```html
Lines 82-122 of the vulnerable file.

            <div class="item-name">Organization settings</div>
            <div class="item-subtext">Smoother onboarding and collaboration for larger teams.</div>
          {{/adminNavItem}}
          {{#adminNavItem routeName="newAdminEmailConfig"}}
            <div class="item-name">Email configuration</div>
            <div class="item-subtext">How email gets sent to users.</div>
          {{/adminNavItem}}
          {{#adminNavItem routeName="newAdminPersonalization"}}
            <div class="item-name">Personalization</div>
            <div class="item-subtext">Customize a splash page, terms of service, privacy policy,
                etc.</div>
          {{/adminNavItem}}
          {{#adminNavItem routeName="newAdminPreinstalledApps"}}
            <div class="item-name">Pre-installed apps</div>
            <div class="item-subtext">Choose apps to pre-install for new users.</div>
          {{/adminNavItem}}
          {{#adminNavItem routeName="newAdminAppSources"}}
            <div class="item-name">App sources</div>
            <div class="item-subtext">Where to look for apps and app updates.</div>
          {{/adminNavItem}}
        </ul>
      </li>
      <li>
        <h2>Management</h2>
        <ul class="nav-items">
          {{#adminNavItem routeName="newAdminUsers"}}
            <div class="item-name">Users</div>
            <div class="item-subtext">Manage all users on this Sandstorm installation.</div>
          {{/adminNavItem}}
          {{#adminNavItem routeName="newAdminStatus"}}
            <div class="item-name">System log</div>
            <div class="item-subtext">View Sandstorm's debug log.</div>
          {{/adminNavItem}}
          {{#adminNavItem routeName="newAdminStats"}}
            <div class="item-name">Statistics</div>
            <div class="item-subtext">View usage statistics for this server.</div>
          {{/adminNavItem}}
          {{#adminNavItem routeName="newAdminMaintenance"}}
            <div class="item-name">Maintenance message</div>
            <div class="item-subtext">Communicate potential downtime to users.</div>
          {{/adminNavItem}}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,6 +99,10 @@
             <div class="item-name">App sources</div>
             <div class="item-subtext">Where to look for apps and app updates.</div>
           {{/adminNavItem}}
+          {{#adminNavItem routeName="newAdminNetworking"}}
+            <div class="item-name">Networking</div>
+            <div class="item-subtext">Control how the network is accessed.</div>
+          {{/adminNavItem}}
         </ul>
       </li>
       <li>
```
