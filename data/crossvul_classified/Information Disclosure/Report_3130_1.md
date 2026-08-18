# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 3130_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3130_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 61-114 of the vulnerable file.

if ( empty($_REQUEST['path']) )
{
  if ( ! empty($_REQUEST['fid']) ) {
    $show = empty($_REQUEST['show']) ? 'capture' : $_REQUEST['show'];
    if ( ! empty($_REQUEST['eid'] ) ) {
      $Event = new Event( $_REQUEST['eid'] );
      $Frame = Frame::find_one( array( 'EventId' => $_REQUEST['eid'], 'FrameId' => $_REQUEST['fid'] ) );
      if ( ! $Frame ) {
        Fatal("No Frame found for event(".$_REQUEST['eid'].") and frame id(".$_REQUEST['fid'].")");
      }
      $path = $Event->Path().'/'.sprintf("%'.0".ZM_EVENT_IMAGE_DIGITS.'d',$_REQUEST['fid']).'-'.$show.'.jpg';
    } else {
# If we are only specifying fid, then the fid must be the primary key into the frames table. But when the event is specified, then it is the frame #
      $Frame = new Frame( $_REQUEST['fid'] );
      $Event = new Event( $Frame->EventId() );
      $path = $Event->Path().'/'.sprintf("%'.0".ZM_EVENT_IMAGE_DIGITS.'d',$Frame->FrameId()).'-'.$show.'.jpg';
    }
  } else {
    $errorText = "No image path";
  }
}
else
{
    $path = ZM_DIR_EVENTS . '/' . $_REQUEST['path'];
    if ( !empty($user['MonitorIds']) )
    {
        $imageOk = false;
        $pathMonId = substr( $path, 0, strspn( $path, "1234567890" ) );
        foreach ( preg_split( '/["\'\s]*,["\'\s]*/', $user['MonitorIds'] ) as $monId )
        {
            if ( $pathMonId == $monId )
            {
                $imageOk = true;
                break;
            }
        }
        if ( !$imageOk )
            $errorText = "No image permissions";
    }
}

$scale=0;
if( !empty($_REQUEST['scale']) )
    if (is_numeric($_REQUEST['scale']))
    {
        $x = $_REQUEST['scale'];
        if($x >= 1 and $x <= 400)
            $scale=$x;
    }

$width=0;
if( !empty($_REQUEST['width']) )
    if (is_numeric($_REQUEST['width']))
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,24 +78,23 @@
   } else {
     $errorText = "No image path";
   }
-}
-else
-{
-    $path = ZM_DIR_EVENTS . '/' . $_REQUEST['path'];
-    if ( !empty($user['MonitorIds']) )
-    {
-        $imageOk = false;
-        $pathMonId = substr( $path, 0, strspn( $path, "1234567890" ) );
-        foreach ( preg_split( '/["\'\s]*,["\'\s]*/', $user['MonitorIds'] ) as $monId )
-        {
-            if ( $pathMonId == $monId )
-            {
-                $imageOk = true;
-                break;
+} else {
+    $path = realpath(ZM_DIR_EVENTS . '/' . $_REQUEST['path']);
+    if(strpos($path, ZM_DIR_EVENTS) == 0 && strpos($path, ZM_DIR_EVENTS) === true) {   
+        if ( !empty($user['MonitorIds']) ) {
+            $imageOk = false;
+            $pathMonId = substr( $path, 0, strspn( $path, "1234567890" ) );
+            foreach ( preg_split( '/["\'\s]*,["\'\s]*/', $user['MonitorIds'] ) as $monId ) {
+                if ( $pathMonId == $monId ) {
+                    $imageOk = true;
+                    break;
+                }
             }
+            if ( !$imageOk )
+                $errorText = "No image permissions";
         }
-        if ( !$imageOk )
-            $errorText = "No image permissions";
+    } else {
+            $errorText = "Invalid image path";
     }
 }
 
```
