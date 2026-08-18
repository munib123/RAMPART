# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5424_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5424_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 175-215 of the vulnerable file.

            <td width='30%'>$column1</td>
            <td align='$phpAds_TextAlignRight'>$column2</td>
            <td align='$phpAds_TextAlignRight'>$column3</td>
            <td align='$phpAds_TextAlignRight'>$column4</td>
            <td align='$phpAds_TextAlignRight'>$column5</td>
            <td align='$phpAds_TextAlignRight'>$column6</td>
        </tr>
        <tr height='1'><td colspan='7' bgcolor='#888888'><img src='" . OX::assetPath() . "/images/break.gif' height='1' width='100%'></td></tr>
    ";
}

function MAX_displayNoStatsMessage()
{
    echo "
    <br /><br /><div class='errormessage'><img class='errormessage' src='" . OX::assetPath() . "/images/info.gif' width='16' height='16' border='0' align='absmiddle'>{$GLOBALS['strNoStats']}</div>";
}

function _getHtmlHeaderColumn($title, $name, $pageName, $entityIds, $listorder, $orderdirection, $showColumn = true)
{
    $str = '';
    $entity = _getEntityString($entityIds);
    if ($listorder == $name) {
        if (($orderdirection == '') || ($orderdirection == 'down')) {
            $str = "<a href='$pageName?{$entity}orderdirection=up'><img src='" . OX::assetPath() . "/images/caret-ds.gif' border='0' alt='' title=''></a>";
        } else {
            $str = "<a href='$pageName?{$entity}orderdirection=down'><img src='" . OX::assetPath() . "/images/caret-u.gif' border='0' alt='' title=''></a>";
        }
    }
    return $showColumn ? "<b><a href='$pageName?{$entity}listorder=$name'>$title</a>$str</b>" : '';
}

function _getEntityString($entityIds)
{
    $entity = '';
    if (!empty($entityIds)) {
        $entityArr = array();
        foreach ($entityIds as $entityId => $entityValue) {
            $entityArr[] = "$entityId=$entityValue";
        }
        $entity = implode('&',$entityArr) . '&';
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,7 +192,8 @@
 function _getHtmlHeaderColumn($title, $name, $pageName, $entityIds, $listorder, $orderdirection, $showColumn = true)
 {
     $str = '';
-    $entity = _getEntityString($entityIds);
+    $entity = htmlspecialchars(_getEntityString($entityIds), ENT_QUOTES);
+    $pageName = htmlspecialchars($pageName, ENT_QUOTES);
     if ($listorder == $name) {
         if (($orderdirection == '') || ($orderdirection == 'down')) {
             $str = "<a href='$pageName?{$entity}orderdirection=up'><img src='" . OX::assetPath() . "/images/caret-ds.gif' border='0' alt='' title=''></a>";
@@ -200,7 +201,7 @@
             $str = "<a href='$pageName?{$entity}orderdirection=down'><img src='" . OX::assetPath() . "/images/caret-u.gif' border='0' alt='' title=''></a>";
         }
     }
-    return $showColumn ? "<b><a href='$pageName?{$entity}listorder=$name'>$title</a>$str</b>" : '';
+    return $showColumn ? "<b><a href='$pageName?{$entity}listorder=".urlencode($name)."'>$title</a>$str</b>" : '';
 }
 
 function _getEntityString($entityIds)
@@ -209,9 +210,9 @@
     if (!empty($entityIds)) {
         $entityArr = array();
         foreach ($entityIds as $entityId => $entityValue) {
-            $entityArr[] = "$entityId=$entityValue";
-        }
-        $entity = implode('&',$entityArr) . '&';
+            $entityArr[] = "$entityId=".urlencode($entityValue);
+        }
+        $entity = implode('&', $entityArr) . '&';
     }
 
     return $entity;
```
