# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 2055_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2055_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 7-47 of the vulnerable file.

    </head>
    <body>
        <script type="text/javascript">
        
        function sendMessage(message, url){
            window.setTimeout(function(){
                window.name = message;
                location.href = url + "," + encodeURIComponent(location.protocol + "//" + location.host + location.pathname);
            }, 0);
        }
        
        if (location.hash) {
            if (location.hash.substring(1, 2) === "_") {
                var channel, url, hash = location.href.substring(location.href.indexOf("#") + 3), indexOf = hash.indexOf(",");
                if (indexOf == -1) {
                    channel = hash;
                }
                else {
                    channel = hash.substring(0, indexOf);
                    url = decodeURIComponent(hash.substring(indexOf + 1));
                }
                switch (location.hash.substring(2, 3)) {
                    case "2":
                        // NameTransport local
                        window.parent.parent.easyXDM.Fn.get(channel)(window.name);
                        location.href = url + "#_4" + channel + ",";
                        break;
                    case "3":
                        // NameTransport remote
                        var guest = window.parent.frames["easyXDM_" + channel + "_provider"];
                        if (!guest) {
                            throw new Error("unable to reference window");
                        }
                        guest.easyXDM.Fn.get(channel)(window.name);
                        location.href = url + "#_4" + channel + ",";
                        break;
                    case "4":
                        // NameTransport idle
                        var fn = window.parent.easyXDM.Fn.get(channel + "_load");
                        if (fn) {
                            fn();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,9 @@
                 else {
                     channel = hash.substring(0, indexOf);
                     url = decodeURIComponent(hash.substring(indexOf + 1));
+                    if (url && !/https?:\/\//.test(url)) {
+                        throw new Error('Invalid url');
+                    }
                 }
                 switch (location.hash.substring(2, 3)) {
                     case "2":
```
