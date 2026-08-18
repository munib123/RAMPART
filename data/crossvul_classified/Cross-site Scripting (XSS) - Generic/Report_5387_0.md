# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5387_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5387_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 193-233 of the vulnerable file.

 *                          will be used
 * @return string The HTML to show the 1x1 logging beacon
 */
function MAX_adRenderImageBeacon($logUrl, $beaconId = 'beacon', $userAgent = null)
{
    if (!isset($userAgent) && isset($_SERVER['HTTP_USER_AGENT'])) {
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
    }
    $beaconId .= '_{random}';
    // Add beacon image for logging
    if (isset($userAgent) && preg_match("#Mozilla/(1|2|3|4)#", $userAgent)
        && !preg_match("#compatible#", $userAgent)) {
        $div = "<layer id='{$beaconId}' width='0' height='0' border='0' visibility='hide'>";
        $style = '';
        $divEnd = '</layer>';
    } else {
        $div = "<div id='{$beaconId}' style='position: absolute; left: 0px; top: 0px; visibility: hidden;'>";
        $style = " style='width: 0px; height: 0px;'";
        $divEnd = '</div>';
    }
        $beacon = "$div<img src='".htmlspecialchars($logUrl)."' width='0' height='0' alt=''{$style} />{$divEnd}";
        return $beacon;
}

/**
 * This function builds the HTML code to display an "image" ad (e.g. GIF/JPG/PNG)
 *
 * @param array   $aBanner      The ad-array for the ad to render code for
 * @param int     $zoneId       The zone ID of the zone used to select this ad (if zone-selected)
 * @param string  $source       The "source" parameter passed into the adcall
 * @param string  $ct0          The 3rd party click tracking URL to redirect to after logging
 * @param int     $withText     Should "text below banner" be appended to the generated code
 * @param bookean $logClick     Should this click be logged (clicks in admin should not be logged)
 * @param boolean $logView      Should this view be logged (views in admin should not be logged
 *                              also - 3rd party callback logging should not be logged at view time)
 * @param boolean $useAlt       Should the backup file be used for this code
 * @param boolean $richMedia    Does this invocation method allow for serving 3rd party/html ads
 * @param string  $loc          The "current page" URL
 * @param string  $referer      The "referring page" URL
 * @param boolean $useAppend    Should any appended code appended to the banner be output?
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -210,7 +210,7 @@
         $style = " style='width: 0px; height: 0px;'";
         $divEnd = '</div>';
     }
-        $beacon = "$div<img src='".htmlspecialchars($logUrl)."' width='0' height='0' alt=''{$style} />{$divEnd}";
+        $beacon = "$div<img src='".htmlspecialchars($logUrl, ENT_QUOTES)."' width='0' height='0' alt=''{$style} />{$divEnd}";
         return $beacon;
 }
 
@@ -249,7 +249,7 @@
     if (!empty($clickUrl)) {  // There is a link
         $status = _adRenderBuildStatusCode($aBanner);
         //$target = !empty($aBanner['target']) ? $aBanner['target'] : '_blank';
-        $clickTag = "<a href='$clickUrl' target='{target}'$status>";
+        $clickTag = "<a href='".htmlspecialchars($clickUrl, ENT_QUOTES)."' target='{target}'$status>";
         $clickTagEnd = '</a>';
     } else {
         $clickTag = '';
@@ -261,7 +261,7 @@
         $width = !empty($aBanner['width']) ? $aBanner['width'] : 0;
         $height = !empty($aBanner['height']) ? $aBanner['height'] : 0;
         $alt = !empty($aBanner['alt']) ? htmlspecialchars($aBanner['alt'], ENT_QUOTES) : '';
-        $imageTag = "$clickTag<img src='$imageUrl' width='$width' height='$height' alt='$alt' title='$alt' border='0'$imgStatus />$clickTagEnd";
+        $imageTag = "$clickTag<img src='".htmlspecialchars($imageUrl, ENT_QUOTES)."' width='$width' height='$height' alt='$alt' title='$alt' border='0'$imgStatus />$clickTagEnd";
     } else {
         $imageTag = '';
     }
@@ -324,7 +324,7 @@
         $status = _adRenderBuildStatusCode($aBanner);
         $target = !empty($aBanner['target']) ? $aBanner['target'] : '_blank';
         $swfParams = array('clickTARGET' => $target, 'clickTAG' => $clickUrl);
-        $clickTag = "<a href='$clickUrl' target='$target'$status>";
+        $clickTag = "<a href='".htmlspecialchars($clickUrl, ENT_QUOTES)."' target='$target'$status>";
         $clickTagEnd = '</a>';
     } else {
         $swfParams = array();
```
