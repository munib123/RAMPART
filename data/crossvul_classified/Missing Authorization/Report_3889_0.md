# CrossVul Fix Pair: Missing Authorization in java
**Pair ID:** 3889_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3889_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 1-23 of the vulnerable file.

package com.eebbk.greenbrowser.util;

import android.content.Intent;
import android.net.Uri;
import android.webkit.WebView;
import android.webkit.WebViewClient;

@SuppressWarnings("unused")
class MyWebViewClient extends WebViewClient {

    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        Uri uri = Uri.parse(url);
        if (uri.getHost() != null && uri.getHost().endsWith("example.com")) {
            return false;
        }

        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        view.getContext().startActivity(intent);
        return true;
    }
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,7 @@
     @Override
     public boolean shouldOverrideUrlLoading(WebView view, String url) {
         Uri uri = Uri.parse(url);
-        if (uri.getHost() != null && uri.getHost().endsWith("example.com")) {
+        if (uri.getHost() != null && uri.getHost().endsWith(".example.com")) {
             return false;
         }
 
```
