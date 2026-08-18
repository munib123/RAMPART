# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 5387_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5387_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 46-86 of the vulnerable file.

          All <em>{$zonescounts.showing}</em> zones on this page selected. <a href="#">Select all <em>{$zonescounts.matching}</em> matching zones from this account.</a>
        </div>
        <div id="zones-{$status}-all-selected" class="selectAllInAccount hide">
          All <em>{$zonescounts.matching}</em> matching zones from this account selected. <a href="#">Clear selection</a></a>
        </div>
      </th>
    </tr>
  </tbody>
  {/if}

  <tbody id="zones-{$status}-rows">
    {foreach from=$websites key=websiteid item=website}
    <tr class="website">
      <td class="name" title="{$website.name|escape}">
        <label style="white-space: nowrap">
            <input id="{$checkboxPrefix}w{$websiteid}"
                   name="w{$websiteid}" type="checkbox" class="checkbox parent" />{boldSearchPhrase text=$website.name search=$text}
        </label>
      </td>
      <td class="link">
          <a title="{t str=EditWebsite} {$website.name}" class="website-icon" href="affiliate-edit.php?affiliateid={$websiteid}">&nbsp;</a>
      </td>
      {if !empty($showStats)}
          <td></td>
          <td></td>
          <td></td>
      {/if}
    </tr>

      {foreach from=$website.zones key=zoneid item=zone}
      <tr class="zone {if $aZonesIdHash[$zoneid]} just-linked{/if}">
        <td class="name" title="{$zone.name|escape}">
        <label>
            <input id="{$checkboxPrefix}w{$websiteid}_z{$zoneid}"
                   name="z{$zoneid}" type="checkbox" class="checkbox" />
            {boldSearchPhrase text=$zone.name search=$text}
        </label>
        </td>
        <td class="link">
            <a title="{t str=EditZone} {$website.name}" class="zone-icon" href="zone-edit.php?affiliateid={$websiteid}&zoneid={$zoneid}">&nbsp;</a>
        </td>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,7 @@
         </label>
       </td>
       <td class="link">
-          <a title="{t str=EditWebsite} {$website.name}" class="website-icon" href="affiliate-edit.php?affiliateid={$websiteid}">&nbsp;</a>
+          <a title="{t str=EditWebsite} {$website.name|escape}" class="website-icon" href="affiliate-edit.php?affiliateid={$websiteid}">&nbsp;</a>
       </td>
       {if !empty($showStats)}
           <td></td>
@@ -82,7 +82,7 @@
         </label>
         </td>
         <td class="link">
-            <a title="{t str=EditZone} {$website.name}" class="zone-icon" href="zone-edit.php?affiliateid={$websiteid}&zoneid={$zoneid}">&nbsp;</a>
+            <a title="{t str=EditZone} {$website.name|escape}" class="zone-icon" href="zone-edit.php?affiliateid={$websiteid}&zoneid={$zoneid}">&nbsp;</a>
         </td>
         {if !empty($showStats)}
             {assign var="ctr" value="`$zone.ctr*100`"}
```
