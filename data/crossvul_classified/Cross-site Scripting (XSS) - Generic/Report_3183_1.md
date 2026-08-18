# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3183_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3183_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<html>
  <body>
    <div id="jw_wrap_1267721422280">
      <object width="400" height="319" id="jw_player_1267721422280"
      name="jw_player_1267721422280">
        <param name="movie"
        value="non-commercial.swf" />
        <param name="wmode" value="transparent" />
        <param name="allowScriptAccess" value="always" />
        <param name="flashvars" value="file=<?php echo $_GET['entryId']; ?>_1@<?php echo $_GET['streamRemoteId']; ?>&subscribe=true&streamer=rtmp://cp<?php echo $_GET['streamUsername']; ?>.live.edgefcs.net/live/&type=fcsubscribe" />
        <embed id="jw_player__1267721422280"
        name="jw_player__1267721422280"
        src="non-commercial.swf"
        width="400" height="319" allowfullscreen="true"
        wmode="transparent" allowscriptaccess="always"
        flashvars="file=<?php echo $_GET['entryId']; ?>_1@<?php echo $_GET['streamRemoteId']; ?>&subscribe=true&streamer=rtmp://cp<?php echo $_GET['streamUsername']; ?>.live.edgefcs.net/live/&type=fcsubscribe" />
        <noembed>
          <a href="http://www.kaltura.org/">Open Source Video</a>
        </noembed>
      </object>
    </div>
  </body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,13 +7,13 @@
         value="non-commercial.swf" />
         <param name="wmode" value="transparent" />
         <param name="allowScriptAccess" value="always" />
-        <param name="flashvars" value="file=<?php echo $_GET['entryId']; ?>_1@<?php echo $_GET['streamRemoteId']; ?>&subscribe=true&streamer=rtmp://cp<?php echo $_GET['streamUsername']; ?>.live.edgefcs.net/live/&type=fcsubscribe" />
+        <param name="flashvars" value="file=<?php echo strip_tags($_GET['entryId']); ?>_1@<?php echo strip_tags($_GET['streamRemoteId']); ?>&subscribe=true&streamer=rtmp://cp<?php echo strip_tags($_GET['streamUsername']); ?>.live.edgefcs.net/live/&type=fcsubscribe" />
         <embed id="jw_player__1267721422280"
         name="jw_player__1267721422280"
         src="non-commercial.swf"
         width="400" height="319" allowfullscreen="true"
         wmode="transparent" allowscriptaccess="always"
-        flashvars="file=<?php echo $_GET['entryId']; ?>_1@<?php echo $_GET['streamRemoteId']; ?>&subscribe=true&streamer=rtmp://cp<?php echo $_GET['streamUsername']; ?>.live.edgefcs.net/live/&type=fcsubscribe" />
+        flashvars="file=<?php echo strip_tags($_GET['entryId']); ?>_1@<?php echo strip_tags($_GET['streamRemoteId']); ?>&subscribe=true&streamer=rtmp://cp<?php echo strip_tags($_GET['streamUsername']); ?>.live.edgefcs.net/live/&type=fcsubscribe" />
         <noembed>
           <a href="http://www.kaltura.org/">Open Source Video</a>
         </noembed>
```
